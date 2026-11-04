/*
 * QEMU PC keyboard emulation
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

uint32_t get_uticks();
static int after_eq(uint32_t a, uint32_t b)
{
    return (a - b) < (1u << 31);
}

#include "i8042.h"

#ifdef BUILD_ESP32
#define THREAD_SAFE
#include <stdatomic.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#endif

/* debug PC keyboard */
//#define DEBUG_KBD

/* debug PC keyboard : only mouse */
//#define DEBUG_MOUSE

/*	Keyboard Controller Commands */
#define KBD_CCMD_READ_MODE	0x20	/* Read mode bits */
#define KBD_CCMD_WRITE_MODE	0x60	/* Write mode bits */
#define KBD_CCMD_GET_VERSION	0xA1	/* Get controller version */
#define KBD_CCMD_MOUSE_DISABLE	0xA7	/* Disable mouse interface */
#define KBD_CCMD_MOUSE_ENABLE	0xA8	/* Enable mouse interface */
#define KBD_CCMD_TEST_MOUSE	0xA9	/* Mouse interface test */
#define KBD_CCMD_SELF_TEST	0xAA	/* Controller self test */
#define KBD_CCMD_KBD_TEST	0xAB	/* Keyboard interface test */
#define KBD_CCMD_KBD_DISABLE	0xAD	/* Keyboard interface disable */
#define KBD_CCMD_KBD_ENABLE	0xAE	/* Keyboard interface enable */
#define KBD_CCMD_READ_INPORT    0xC0    /* read input port */
#define KBD_CCMD_READ_OUTPORT	0xD0    /* read output port */
#define KBD_CCMD_WRITE_OUTPORT	0xD1    /* write output port */
#define KBD_CCMD_WRITE_OBUF	0xD2
#define KBD_CCMD_WRITE_AUX_OBUF	0xD3    /* Write to output buffer as if
					   initiated by the auxiliary device */
#define KBD_CCMD_WRITE_MOUSE	0xD4	/* Write the following byte to the mouse */
#define KBD_CCMD_DISABLE_A20    0xDD    /* HP vectra only ? */
#define KBD_CCMD_ENABLE_A20     0xDF    /* HP vectra only ? */
#define KBD_CCMD_RESET	        0xFE

/* Status Register Bits */
#define KBD_STAT_OBF 		0x01	/* Keyboard output buffer full */
#define KBD_STAT_IBF 		0x02	/* Keyboard input buffer full */
#define KBD_STAT_SELFTEST	0x04	/* Self test successful */
#define KBD_STAT_CMD		0x08	/* Last write was a command write (0=data) */
#define KBD_STAT_UNLOCKED	0x10	/* Zero if keyboard locked */
#define KBD_STAT_MOUSE_OBF	0x20	/* Mouse output buffer full */
#define KBD_STAT_GTO 		0x40	/* General receive/xmit timeout */
#define KBD_STAT_PERR 		0x80	/* Parity error */

/* Controller Mode Register Bits */
#define KBD_MODE_KBD_INT	0x01	/* Keyboard data generate IRQ1 */
#define KBD_MODE_MOUSE_INT	0x02	/* Mouse data generate IRQ12 */
#define KBD_MODE_SYS 		0x04	/* The system flag (?) */
#define KBD_MODE_NO_KEYLOCK	0x08	/* The keylock doesn't affect the keyboard if set */
#define KBD_MODE_DISABLE_KBD	0x10	/* Disable keyboard interface */
#define KBD_MODE_DISABLE_MOUSE	0x20	/* Disable mouse interface */
#define KBD_MODE_KCC 		0x40	/* Scan code conversion to PC format */
#define KBD_MODE_RFU		0x80

#define KBD_PENDING_KBD         1
#define KBD_PENDING_AUX         2

struct KBDState {
    uint8_t write_cmd; /* if non zero, write data to port 60 is expected */
    uint8_t status;
    uint8_t mode;
    /* Bitmask of devices with data available.  */
    uint8_t pending;
    PS2KbdState *kbd;
    PS2MouseState *mouse;

    int irq_kbd;
    int irq_mouse;
    void *pic;
    void (*set_irq)(void *pic, int irq, int level);
    void *sys;
    void (*system_reset_request)(void *sys);
};

static void ioport_set_a20(int val)
{
}

static int ioport_get_a20(void)
{
    return 1;
}

/* update irq and KBD_STAT_[MOUSE_]OBF */
/* XXX: not generating the irqs if KBD_MODE_DISABLE_KBD is set may be
   incorrect, but it avoids having to simulate exact delays */
static void kbd_update_irq(KBDState *s)
{
    int irq_kbd_level, irq_mouse_level;

    irq_kbd_level = 0;
    irq_mouse_level = 0;
    s->status &= ~(KBD_STAT_OBF | KBD_STAT_MOUSE_OBF);
    if (s->pending) {
        s->status |= KBD_STAT_OBF;
        /* kbd data takes priority over aux data.  */
        if (s->pending == KBD_PENDING_AUX) {
            s->status |= KBD_STAT_MOUSE_OBF;
            if (s->mode & KBD_MODE_MOUSE_INT)
                irq_mouse_level = 1;
        } else {
            if ((s->mode & KBD_MODE_KBD_INT) &&
                !(s->mode & KBD_MODE_DISABLE_KBD))
                irq_kbd_level = 1;
        }
    }
    s->set_irq(s->pic, s->irq_kbd, irq_kbd_level);
    s->set_irq(s->pic, s->irq_mouse, irq_mouse_level);
}

static void kbd_update_kbd_irq(void *opaque, int level)
{
    KBDState *s = (KBDState *)opaque;

    if (level)
        s->pending |= KBD_PENDING_KBD;
    else
        s->pending &= ~KBD_PENDING_KBD;
    kbd_update_irq(s);
}

static void kbd_update_aux_irq(void *opaque, int level)
{
    KBDState *s = (KBDState *)opaque;

    if (level)
        s->pending |= KBD_PENDING_AUX;
    else
        s->pending &= ~KBD_PENDING_AUX;
    kbd_update_irq(s);
}

uint32_t kbd_read_status(void *opaque, uint32_t addr)
{
    KBDState *s = opaque;
    int val;
    val = s->status;
#if defined(DEBUG_KBD)
    printf("kbd: read status=0x%02x\n", val);
#endif
    return val;
}

static void kbd_queue(KBDState *s, int b, int aux)
{
    if (aux)
        ps2_queue(s->mouse, b);
    else
        ps2_queue(s->kbd, b);
}

void kbd_write_command(void *opaque, uint32_t addr, uint32_t val)
{
    KBDState *s = opaque;

#if defined(DEBUG_KBD)
    printf("kbd: write cmd=0x%02x\n", val);
#endif
    switch(val) {
    case KBD_CCMD_READ_MODE:
        kbd_queue(s, s->mode, 1);
        break;
    case KBD_CCMD_WRITE_MODE:
    case KBD_CCMD_WRITE_OBUF:
    case KBD_CCMD_WRITE_AUX_OBUF:
    case KBD_CCMD_WRITE_MOUSE:
    case KBD_CCMD_WRITE_OUTPORT:
        s->write_cmd = val;
        break;
    case KBD_CCMD_MOUSE_DISABLE:
        s->mode |= KBD_MODE_DISABLE_MOUSE;
        break;
    case KBD_CCMD_MOUSE_ENABLE:
        s->mode &= ~KBD_MODE_DISABLE_MOUSE;
        break;
    case KBD_CCMD_TEST_MOUSE:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_SELF_TEST:
        s->status |= KBD_STAT_SELFTEST;
        kbd_queue(s, 0x55, 0);
        break;
    case KBD_CCMD_KBD_TEST:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_KBD_DISABLE:
        s->mode |= KBD_MODE_DISABLE_KBD;
        kbd_update_irq(s);
        break;
    case KBD_CCMD_KBD_ENABLE:
        s->mode &= ~KBD_MODE_DISABLE_KBD;
        kbd_update_irq(s);
        break;
    case KBD_CCMD_READ_INPORT:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_READ_OUTPORT:
        /* XXX: check that */
        val = 0x01 | (ioport_get_a20() << 1);
        if (s->status & KBD_STAT_OBF)
            val |= 0x10;
        if (s->status & KBD_STAT_MOUSE_OBF)
            val |= 0x20;
        kbd_queue(s, val, 0);
        break;
    case KBD_CCMD_ENABLE_A20:
        ioport_set_a20(1);
        break;
    case KBD_CCMD_DISABLE_A20:
        ioport_set_a20(0);
        break;
    case KBD_CCMD_RESET:
        s->system_reset_request(s->sys);
        break;
    case 0xff:
        /* ignore that - I don't know what is its use */
        break;
    default:
        fprintf(stderr, "qemu: unsupported keyboard cmd=0x%02x\n", val);
        break;
    }
}

uint32_t kbd_read_data(void *opaque, uint32_t addr)
{
    KBDState *s = opaque;
    uint32_t val;
    if (s->pending == KBD_PENDING_AUX)
        val = ps2_read_data(s->mouse);
    else
        val = ps2_read_data(s->kbd);
#ifdef DEBUG_KBD
    printf("kbd: read data=0x%02x\n", val);
#endif
    return val;
}

void kbd_write_data(void *opaque, uint32_t addr, uint32_t val)
{
    KBDState *s = opaque;

#ifdef DEBUG_KBD
    printf("kbd: write data=0x%02x\n", val);
#endif

    switch(s->write_cmd) {
    case 0:
        ps2_write_keyboard(s->kbd, val);
        break;
    case KBD_CCMD_WRITE_MODE:
        s->mode = val;
        ps2_keyboard_set_translation(s->kbd, (s->mode & KBD_MODE_KCC) != 0);
        /* ??? */
        kbd_update_irq(s);
        break;
    case KBD_CCMD_WRITE_OBUF:
        kbd_queue(s, val, 0);
        break;
    case KBD_CCMD_WRITE_AUX_OBUF:
        kbd_queue(s, val, 1);
        break;
    case KBD_CCMD_WRITE_OUTPORT:
        ioport_set_a20((val >> 1) & 1);
        if (!(val & 1)) {
            s->system_reset_request(s->sys);
        }
        break;
    case KBD_CCMD_WRITE_MOUSE:
        ps2_write_mouse(s->mouse, val);
        break;
    default:
        break;
    }
    s->write_cmd = 0;
}

static void kbd_reset(void *opaque)
{
    KBDState *s = opaque;

    s->mode = KBD_MODE_KBD_INT | KBD_MODE_MOUSE_INT | KBD_MODE_KCC;
    s->status = KBD_STAT_CMD | KBD_STAT_UNLOCKED;
}

KBDState *i8042_init(PS2KbdState **pkbd,
                     PS2MouseState **pmouse,
                     int kbd_irq, int mouse_irq,
                     void *pic,
                     void (*set_irq)(void *pic, int irq, int level),
                     void *sys,
                     void (*system_reset_request)(void *sys))
{
    KBDState *s;
    
    s = malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    
    s->irq_kbd = kbd_irq;
    s->irq_mouse = mouse_irq;
    s->pic = pic;
    s->set_irq = set_irq;
    s->sys = sys;
    s->system_reset_request = system_reset_request;

    kbd_reset(s);

    s->kbd = ps2_kbd_init(kbd_update_kbd_irq, s);
    s->mouse = ps2_mouse_init(kbd_update_aux_irq, s);

    *pkbd = s->kbd;
    *pmouse = s->mouse;
    return s;
}

/*
 * QEMU PS/2 keyboard/mouse emulation
 *
 * Copyright (c) 2003 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

//#include "cutils.h"
//#include "iomem.h"
//#include "ps2.h"

/* debug PC keyboard */
//#define DEBUG_KBD

/* debug PC keyboard : only mouse */
//#define DEBUG_MOUSE

/* Keyboard Commands */
#define KBD_CMD_SET_LEDS	0xED	/* Set keyboard leds */
#define KBD_CMD_ECHO     	0xEE
#define KBD_CMD_GET_ID 	        0xF2	/* get keyboard ID */
#define KBD_CMD_SET_RATE	0xF3	/* Set typematic rate */
#define KBD_CMD_ENABLE		0xF4	/* Enable scanning */
#define KBD_CMD_RESET_DISABLE	0xF5	/* reset and disable scanning */
#define KBD_CMD_RESET_ENABLE   	0xF6    /* reset and enable scanning */
#define KBD_CMD_RESET		0xFF	/* Reset */

/* Keyboard Replies */
#define KBD_REPLY_POR		0xAA	/* Power on reset */
#define KBD_REPLY_ACK		0xFA	/* Command ACK */
#define KBD_REPLY_RESEND	0xFE	/* Command NACK, send the cmd again */

/* Mouse Commands */
#define AUX_SET_SCALE11		0xE6	/* Set 1:1 scaling */
#define AUX_SET_SCALE21		0xE7	/* Set 2:1 scaling */
#define AUX_SET_RES		0xE8	/* Set resolution */
#define AUX_GET_SCALE		0xE9	/* Get scaling factor */
#define AUX_SET_STREAM		0xEA	/* Set stream mode */
#define AUX_POLL		0xEB	/* Poll */
#define AUX_RESET_WRAP		0xEC	/* Reset wrap mode */
#define AUX_SET_WRAP		0xEE	/* Set wrap mode */
#define AUX_SET_REMOTE		0xF0	/* Set remote mode */
#define AUX_GET_TYPE		0xF2	/* Get type */
#define AUX_SET_SAMPLE		0xF3	/* Set sample rate */
#define AUX_ENABLE_DEV		0xF4	/* Enable aux device */
#define AUX_DISABLE_DEV		0xF5	/* Disable aux device */
#define AUX_SET_DEFAULT		0xF6
#define AUX_RESET		0xFF	/* Reset aux device */
#define AUX_ACK			0xFA	/* Command byte ACK. */

#define MOUSE_STATUS_REMOTE     0x40
#define MOUSE_STATUS_ENABLED    0x20
#define MOUSE_STATUS_SCALE21    0x10

#define PS2_QUEUE_SIZE 256

typedef struct {
    uint8_t data[PS2_QUEUE_SIZE];
    int rptr, wptr, count;
#ifdef THREAD_SAFE
    SemaphoreHandle_t mutex;
#endif
} PS2Queue;

typedef struct {
    PS2Queue queue;
    int32_t write_cmd;
    void (*update_irq)(void *, int);
    void *update_arg;
} PS2State;

struct  PS2KbdState {
    PS2State common;
    int scan_enabled;
    /* Qemu uses translated PC scancodes internally.  To avoid multiple
       conversions we do the translation (if any) in the PS/2 emulation
       not the keyboard controller.  */
    int translate;
    int translate_state;
    bool delay;
    uint32_t delay_time;
    int delay_keycode;
#ifdef THREAD_SAFE
    atomic_flag delay_flag;
#endif
};

struct PS2MouseState {
    PS2State common;
    uint8_t mouse_status;
    uint8_t mouse_resolution;
    uint8_t mouse_sample_rate;
    uint8_t mouse_wrap;
    uint8_t mouse_type; /* 0 = PS2, 3 = IMPS/2, 4 = IMEX */
    uint8_t mouse_detect_state;
    int mouse_dx; /* current values, needed for 'poll' mode */
    int mouse_dy;
    int mouse_dz;
    uint8_t mouse_buttons;
    uint8_t mouse_pending; /* a packet found no room: send with the next event */
    uint32_t last_report; /* get_uticks() at the last packet sent */
};

void ps2_queue(void *opaque, int b)
{
    PS2State *s = (PS2State *)opaque;
    PS2Queue *q = &s->queue;

#ifdef THREAD_SAFE
    xSemaphoreTake(q->mutex, portMAX_DELAY);
#endif

    if (q->count >= PS2_QUEUE_SIZE) {
        /* full: the byte is lost, as on a real keyboard, but the queue
           must not stay locked, or the next ps2_queue() or
           ps2_read_data() waits for ever */
#ifdef THREAD_SAFE
        xSemaphoreGive(q->mutex);
#endif
        return;
    }
    q->data[q->wptr] = b;
    if (++q->wptr == PS2_QUEUE_SIZE)
        q->wptr = 0;
    q->count++;

#ifdef THREAD_SAFE
    xSemaphoreGive(q->mutex);
#else
    s->update_irq(s->update_arg, 1);
#endif
}

static const uint8_t scancode1_to_2_table[0x60] = {
    [0x00] = 0x00, [0x01] = 0x76, [0x02] = 0x16, [0x03] = 0x1E,
    [0x04] = 0x26, [0x05] = 0x25, [0x06] = 0x2E, [0x07] = 0x36,
    [0x08] = 0x3D, [0x09] = 0x3E, [0x0A] = 0x46, [0x0B] = 0x45,
    [0x0C] = 0x4E, [0x0D] = 0x55, [0x0E] = 0x66, [0x0F] = 0x0D,
    [0x10] = 0x15, [0x11] = 0x1D, [0x12] = 0x24, [0x13] = 0x2D,
    [0x14] = 0x2C, [0x15] = 0x35, [0x16] = 0x3C, [0x17] = 0x43,
    [0x18] = 0x44, [0x19] = 0x4D, [0x1A] = 0x54, [0x1B] = 0x5B,
    [0x1C] = 0x5A, [0x1D] = 0x14, [0x1E] = 0x1C, [0x1F] = 0x1B,
    [0x20] = 0x23, [0x21] = 0x2B, [0x22] = 0x34, [0x23] = 0x33,
    [0x24] = 0x3B, [0x25] = 0x42, [0x26] = 0x4B, [0x27] = 0x4C,
    [0x28] = 0x52, [0x29] = 0x0E, [0x2A] = 0x12, [0x2B] = 0x5D,
    [0x2C] = 0x1A, [0x2D] = 0x22, [0x2E] = 0x21, [0x2F] = 0x2A,
    [0x30] = 0x32, [0x31] = 0x31, [0x32] = 0x3A, [0x33] = 0x41,
    [0x34] = 0x49, [0x35] = 0x4A, [0x36] = 0x59, [0x37] = 0x7C,
    [0x38] = 0x11, [0x39] = 0x29, [0x3A] = 0x58, [0x3B] = 0x05,
    [0x3C] = 0x06, [0x3D] = 0x04, [0x3E] = 0x0C, [0x3F] = 0x03,
    [0x40] = 0x0B, [0x41] = 0x83, [0x42] = 0x0A, [0x43] = 0x01,
    [0x44] = 0x09, [0x45] = 0x77, [0x46] = 0x7E, [0x47] = 0x6C,
    [0x48] = 0x75, [0x49] = 0x7D, [0x4A] = 0x7B, [0x4B] = 0x6B,
    [0x4C] = 0x73, [0x4D] = 0x74, [0x4E] = 0x79, [0x4F] = 0x69,
    [0x50] = 0x72, [0x51] = 0x7A, [0x52] = 0x70, [0x53] = 0x71,
    [0x57] = 0x78, [0x58] = 0x07
};

static uint8_t convert_extended_scancode(uint8_t core_code) {
    switch (core_code) {
        case 0x5E: return 0x37;
        case 0x5F: return 0x3F;
        case 0x63: return 0x5E;
        case 0x20: return 0x23;
        case 0x2E: return 0x21;
        case 0x30: return 0x32;
        case 0x10: return 0x15;
        case 0x19: return 0x4D;
        case 0x22: return 0x34;
        case 0x24: return 0x3B;
        case 0x6A: return 0x3A;
        case 0x69: return 0x31;
        case 0x68: return 0x28;
        case 0x67: return 0x20;
        case 0x65: return 0x10;
        case 0x66: return 0x18;
        case 0x32: return 0x3A;
        case 0x6C: return 0x48;
        case 0x21: return 0x2B;
        case 0x6B: return 0x40;
        case 0x1C: return 0x5A;
        case 0x1D: return 0x14;
        case 0x35: return 0x4A;
        case 0x38: return 0x11;
        case 0x52: return 0x70;
        case 0x53: return 0x71;
        case 0x47: return 0x6C;
        case 0x4F: return 0x69;
        case 0x49: return 0x7D;
        case 0x51: return 0x7A;
        case 0x48: return 0x75;
        case 0x50: return 0x72;
        case 0x4B: return 0x6B;
        case 0x4D: return 0x74;
        case 0x5B: return 0x1F;
        case 0x5C: return 0x27;
        case 0x5D: return 0x2F;
        default:   return 0x00;
    }
}

void ps2_queue_sc(void *opaque, int code)
{
    PS2KbdState *s = opaque;
    if (s->translate) {
        ps2_queue(s, code);
        return;
    }

    if (code == 0xE0) {
        s->translate_state = 1;
        return;
    }

    bool is_break = !!(code & 0x80);
    uint8_t core = code & 0x7F;

    if (s->translate_state == 1) {
        s->translate_state = 0;
        uint8_t sc2_core = convert_extended_scancode(core);
        if (sc2_core == 0) return;

        ps2_queue(s, 0xE0);
        if (is_break)
            ps2_queue(s, 0xF0);
        ps2_queue(s, sc2_core);
    }
    else {
        if (core >= 0x60) return;
        uint8_t sc2_core = scancode1_to_2_table[core];
        if (sc2_core == 0) return;

        if (is_break)
            ps2_queue(s, 0xF0);
        ps2_queue(s, sc2_core);
    }
}

#define INPUT_MAKE_KEY_MIN 96
#define INPUT_MAKE_KEY_MAX 127

static const uint8_t linux_input_to_keycode_set1[INPUT_MAKE_KEY_MAX - INPUT_MAKE_KEY_MIN + 1] = {
    0x1c, 0x1d, 0x35, 0x00, 0x38, 0x00, 0x47, 0x48, 
    0x49, 0x4b, 0x4d, 0x4f, 0x50, 0x51, 0x52, 0x53, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x5c, 0x5d, 
};

/* keycode is a Linux input layer keycode. We only support the PS/2
   keycode set 1 */
void ps2_put_keycode(PS2KbdState *s, int is_down, int keycode)
{
#ifdef THREAD_SAFE
    while (atomic_flag_test_and_set_explicit(&(s->delay_flag),
                                             memory_order_acquire)) {}
#endif

    if (s->delay) {
        s->delay = false;
        ps2_queue_sc(&s->common, s->delay_keycode);
    }

    if (keycode >= 0xe000) {
        ps2_queue_sc(&s->common, keycode >> 8);
        s->delay = true;
        s->delay_time = get_uticks() + 10000;
        s->delay_keycode = (keycode & 0xff) | ((!is_down) << 7);
    } else if (keycode >= INPUT_MAKE_KEY_MIN) {
        if (keycode > INPUT_MAKE_KEY_MAX)
            goto out;
        keycode = linux_input_to_keycode_set1[keycode - INPUT_MAKE_KEY_MIN];
        if (keycode == 0)
            goto out;
        ps2_queue_sc(&s->common, 0xe0);
        /* XXX: currently the ps2 queue is driven by data reading,
           however the "e0" prefix may be read by some old DOS
           software more than once, The workaround is to send the
           second keycode later, so that the guest software can read
           the same data again. */
        s->delay = true;
        s->delay_time = get_uticks() + 1000;
        s->delay_keycode = keycode | ((!is_down) << 7);
    } else {
        ps2_queue_sc(&s->common, keycode | ((!is_down) << 7));
    }

out:;
#ifdef THREAD_SAFE
    atomic_flag_clear_explicit(&(s->delay_flag), memory_order_release);
#endif
}

/* to be called in main loop */
void kbd_step(void *opaque)
{
    KBDState *s = opaque;
    PS2KbdState *kbd = s->kbd;
#ifdef THREAD_SAFE
    if (!atomic_flag_test_and_set_explicit(&(kbd->delay_flag),
                                           memory_order_acquire)) {
#endif

    if (kbd->delay && after_eq(get_uticks(), kbd->delay_time)) {
        kbd->delay = false;
        ps2_queue_sc(&(kbd->common), kbd->delay_keycode);
    }

#ifdef THREAD_SAFE
    atomic_flag_clear_explicit(&(kbd->delay_flag), memory_order_release);
    }
#endif
#ifdef THREAD_SAFE
    if (s->kbd->common.queue.count)
        s->kbd->common.update_irq(s->kbd->common.update_arg, 1);
    if (s->mouse->common.queue.count)
        s->mouse->common.update_irq(s->mouse->common.update_arg, 1);
#endif
}

uint32_t ps2_read_data(void *opaque)
{
    PS2State *s = (PS2State *)opaque;
    PS2Queue *q;
    int val, index;

    q = &s->queue;
#ifdef THREAD_SAFE
    xSemaphoreTake(q->mutex, portMAX_DELAY);
#endif
    if (q->count == 0) {
        /* NOTE: if no data left, we return the last keyboard one
           (needed for EMM386) */
        /* XXX: need a timer to do things correctly */
        index = q->rptr - 1;
        if (index < 0)
            index = PS2_QUEUE_SIZE - 1;
        val = q->data[index];
    } else {
        val = q->data[q->rptr];
        if (++q->rptr == PS2_QUEUE_SIZE)
            q->rptr = 0;
        q->count--;
        /* reading deasserts IRQ */
        s->update_irq(s->update_arg, 0);
        /* reassert IRQs if data left */
        s->update_irq(s->update_arg, q->count != 0);
    }
#ifdef THREAD_SAFE
    xSemaphoreGive(q->mutex);
#endif
    return val;
}

static void ps2_reset_keyboard(PS2KbdState *s)
{
    s->scan_enabled = 1;
}

void ps2_write_keyboard(void *opaque, int val)
{
    PS2KbdState *s = (PS2KbdState *)opaque;

    switch(s->common.write_cmd) {
    default:
    case -1:
        switch(val) {
        case 0x00:
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        case 0x05:
            ps2_queue(&s->common, KBD_REPLY_RESEND);
            break;
        case KBD_CMD_GET_ID:
            ps2_queue(&s->common, KBD_REPLY_ACK);
            ps2_queue(&s->common, 0xab);
            ps2_queue(&s->common, 0x83);
            break;
        case KBD_CMD_ECHO:
            ps2_queue(&s->common, KBD_CMD_ECHO);
            break;
        case KBD_CMD_ENABLE:
            s->scan_enabled = 1;
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        case KBD_CMD_SET_LEDS:
        case KBD_CMD_SET_RATE:
            s->common.write_cmd = val;
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        case KBD_CMD_RESET_DISABLE:
            ps2_reset_keyboard(s);
            s->scan_enabled = 0;
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        case KBD_CMD_RESET_ENABLE:
            ps2_reset_keyboard(s);
            s->scan_enabled = 1;
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        case KBD_CMD_RESET:
            ps2_reset_keyboard(s);
            ps2_queue(&s->common, KBD_REPLY_ACK);
            ps2_queue(&s->common, KBD_REPLY_POR);
            break;
        default:
            ps2_queue(&s->common, KBD_REPLY_ACK);
            break;
        }
        break;
    case KBD_CMD_SET_LEDS:
        ps2_queue(&s->common, KBD_REPLY_ACK);
        s->common.write_cmd = -1;
        break;
    case KBD_CMD_SET_RATE:
        ps2_queue(&s->common, KBD_REPLY_ACK);
        s->common.write_cmd = -1;
        break;
    }
}

/* Set the scancode translation mode.
   0 = raw scancodes.
   1 = translated scancodes (used by qemu internally).  */

void ps2_keyboard_set_translation(void *opaque, int mode)
{
    PS2KbdState *s = (PS2KbdState *)opaque;
    if (s->translate != mode)
        fprintf(stderr, "i8042: use scancode set %d\n", mode ? 1 : 2);
    s->translate = mode;
    s->translate_state = 0;
}

/* n bytes into the queue, all of them or none: none if headroom places or
   fewer are free, or if the n bytes do not fit.  A mouse packet cut short
   by a full queue would put every packet after it out of step in the
   guest's driver. */
static int ps2_queue_packet(PS2State *s, const uint8_t *b, int n, int headroom)
{
    PS2Queue *q = &s->queue;
    int ok;

#ifdef THREAD_SAFE
    xSemaphoreTake(q->mutex, portMAX_DELAY);
#endif
    ok = q->count < PS2_QUEUE_SIZE - headroom && q->count + n <= PS2_QUEUE_SIZE;
    if (ok) {
        for (int i = 0; i < n; i++) {
            q->data[q->wptr] = b[i];
            if (++q->wptr == PS2_QUEUE_SIZE)
                q->wptr = 0;
        }
        q->count += n;
    }
#ifdef THREAD_SAFE
    xSemaphoreGive(q->mutex);
#else
    if (ok)
        s->update_irq(s->update_arg, 1);
#endif
    return ok;
}

/* One packet of what has not been sent yet, if all of it fits with
   headroom places to spare; 0 if it does not, and nothing is sent. */
static int ps2_mouse_send_packet(PS2MouseState *s, int headroom)
{
    uint8_t p[4];
    int n = 3;
    unsigned int b;
    int dx1, dy1, dz1;

    dx1 = s->mouse_dx;
    dy1 = s->mouse_dy;
    dz1 = s->mouse_dz;
    /* XXX: increase range to 8 bits ? */
    if (dx1 > 127)
        dx1 = 127;
    else if (dx1 < -127)
        dx1 = -127;
    if (dy1 > 127)
        dy1 = 127;
    else if (dy1 < -127)
        dy1 = -127;
    b = 0x08 | ((dx1 < 0) << 4) | ((dy1 < 0) << 5) | (s->mouse_buttons & 0x07);
    p[0] = b;
    p[1] = dx1 & 0xff;
    p[2] = dy1 & 0xff;
    /* extra byte for IMPS/2 or IMEX */
    switch(s->mouse_type) {
    default:
        break;
    case 3:
        if (dz1 > 127)
            dz1 = 127;
        else if (dz1 < -127)
                dz1 = -127;
        p[n++] = dz1 & 0xff;
        break;
    case 4:
        if (dz1 > 7)
            dz1 = 7;
        else if (dz1 < -7)
            dz1 = -7;
        b = (dz1 & 0x0f) | ((s->mouse_buttons & 0x18) << 1);
        p[n++] = b;
        break;
    }
    if (!ps2_queue_packet(&s->common, p, n, headroom))
        return 0;

    /* update deltas */
    s->mouse_dx -= dx1;
    s->mouse_dy -= dy1;
    s->mouse_dz -= dz1;
    return 1;
}

void ps2_mouse_event(PS2MouseState *s,
                     int dx, int dy, int dz, int buttons_state)
{
    /* check if deltas are recorded when disabled */
    if (!(s->mouse_status & MOUSE_STATUS_ENABLED))
        return;

    s->mouse_dx += dx;
    s->mouse_dy -= dy;
    s->mouse_dz += dz;
    /* XXX: SDL sometimes generates nul events: we delete them */
    if (s->mouse_dx == 0 && s->mouse_dy == 0 && s->mouse_dz == 0 &&
        s->mouse_buttons == buttons_state && !s->mouse_pending)
        return;
    int changed = s->mouse_buttons != buttons_state;
    s->mouse_buttons = buttons_state;

    /* As a mouse reports at its sample rate and adds up what it moved
       meanwhile: a packet only when the last has been read and the rate
       the guest set allows it (a tenth early, as events come at the host's
       pace), or for a change of buttons; the rest kept for the next event.
       A guest that reads slowly then gets the movement late, not a queue
       of old packets. The rate matters to Windows 3.1: it asks for 40 a
       second, and its 386 enhanced mode holds 32 bytes for the System VM;
       at 30, it drops the last byte of one packet and the first two of
       the next, so the VM gets one packet's status with the next's Y,
       whose sign is then the other's: the pointer leapt up or down the
       screen while the mouse moved sideways. More than 16 places are kept
       free for replies to commands: a packet that found no room, a change
       of buttons too, is sent with the next event. */
    uint32_t now = get_uticks();
    int rate = s->mouse_sample_rate ? s->mouse_sample_rate : 100;
    if (!(s->mouse_status & MOUSE_STATUS_REMOTE) &&
        ((s->common.queue.count == 0 &&
          now - s->last_report >= 900000u / rate) ||
         changed || s->mouse_pending)) {
        if (ps2_mouse_send_packet(s, 16)) {
            s->mouse_pending = 0;
            s->last_report = now;
        } else {
            s->mouse_pending = 1;
        }
    }
}

void ps2_write_mouse(void *opaque, int val)
{
    PS2MouseState *s = (PS2MouseState *)opaque;
#ifdef DEBUG_MOUSE
    printf("kbd: write mouse 0x%02x\n", val);
#endif
    switch(s->common.write_cmd) {
    default:
    case -1:
        /* mouse command */
        if (s->mouse_wrap) {
            if (val == AUX_RESET_WRAP) {
                s->mouse_wrap = 0;
                ps2_queue(&s->common, AUX_ACK);
                return;
            } else if (val != AUX_RESET) {
                ps2_queue(&s->common, val);
                return;
            }
        }
        switch(val) {
        case AUX_SET_SCALE11:
            s->mouse_status &= ~MOUSE_STATUS_SCALE21;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_SET_SCALE21:
            s->mouse_status |= MOUSE_STATUS_SCALE21;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_SET_STREAM:
            s->mouse_status &= ~MOUSE_STATUS_REMOTE;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_SET_WRAP:
            s->mouse_wrap = 1;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_SET_REMOTE:
            s->mouse_status |= MOUSE_STATUS_REMOTE;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_GET_TYPE:
            ps2_queue(&s->common, AUX_ACK);
            ps2_queue(&s->common, s->mouse_type);
            break;
        case AUX_SET_RES:
        case AUX_SET_SAMPLE:
            s->common.write_cmd = val;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_GET_SCALE:
            ps2_queue(&s->common, AUX_ACK);
            ps2_queue(&s->common, s->mouse_status);
            ps2_queue(&s->common, s->mouse_resolution);
            ps2_queue(&s->common, s->mouse_sample_rate);
            break;
        case AUX_POLL:
            ps2_queue(&s->common, AUX_ACK);
            ps2_mouse_send_packet(s, 0);
            break;
        case AUX_ENABLE_DEV:
            s->mouse_status |= MOUSE_STATUS_ENABLED;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_DISABLE_DEV:
            s->mouse_status &= ~MOUSE_STATUS_ENABLED;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_SET_DEFAULT:
            s->mouse_sample_rate = 100;
            s->mouse_resolution = 2;
            s->mouse_status = 0;
            ps2_queue(&s->common, AUX_ACK);
            break;
        case AUX_RESET:
            s->mouse_sample_rate = 100;
            s->mouse_resolution = 2;
            s->mouse_status = 0;
            s->mouse_type = 0;
            ps2_queue(&s->common, AUX_ACK);
            ps2_queue(&s->common, 0xaa);
            ps2_queue(&s->common, s->mouse_type);
            break;
        default:
            break;
        }
        break;
    case AUX_SET_SAMPLE:
        s->mouse_sample_rate = val;
        /* detect IMPS/2 or IMEX */
        switch(s->mouse_detect_state) {
        default:
        case 0:
            if (val == 200)
                s->mouse_detect_state = 1;
            break;
        case 1:
            if (val == 100)
                s->mouse_detect_state = 2;
            else if (val == 200)
                s->mouse_detect_state = 3;
            else
                s->mouse_detect_state = 0;
            break;
        case 2:
            if (val == 80)
                s->mouse_type = 3; /* IMPS/2 */
            s->mouse_detect_state = 0;
            break;
        case 3:
            if (val == 80)
                s->mouse_type = 4; /* IMEX */
            s->mouse_detect_state = 0;
            break;
        }
        ps2_queue(&s->common, AUX_ACK);
        s->common.write_cmd = -1;
        break;
    case AUX_SET_RES:
        s->mouse_resolution = val;
        ps2_queue(&s->common, AUX_ACK);
        s->common.write_cmd = -1;
        break;
    }
}

static void ps2_reset(void *opaque)
{
    PS2State *s = (PS2State *)opaque;
    PS2Queue *q;
    s->write_cmd = -1;
    q = &s->queue;
    q->rptr = 0;
    q->wptr = 0;
    q->count = 0;
#ifdef THREAD_SAFE
    s->queue.mutex = xSemaphoreCreateMutex();
#endif
}

PS2KbdState *ps2_kbd_init(void (*update_irq)(void *, int), void *update_arg)
{
    PS2KbdState *s = (PS2KbdState *)malloc(sizeof(PS2KbdState));
    memset(s, 0, sizeof(PS2KbdState));
#ifdef THREAD_SAFE
    atomic_flag_clear(&(s->delay_flag));
#endif

    s->common.update_irq = update_irq;
    s->common.update_arg = update_arg;
    ps2_reset(&s->common);
    return s;
}

PS2MouseState *ps2_mouse_init(void (*update_irq)(void *, int), void *update_arg)
{
    PS2MouseState *s = (PS2MouseState *)malloc(sizeof(PS2MouseState));
    memset(s, 0, sizeof(PS2MouseState));

    s->common.update_irq = update_irq;
    s->common.update_arg = update_arg;
    ps2_reset(&s->common);
    return s;
}
