#ifndef I8042_H
#define I8042_H

typedef struct PS2MouseState PS2MouseState;
typedef struct PS2KbdState PS2KbdState;

PS2KbdState *ps2_kbd_init(void (*update_irq)(void *, int), void *update_arg);
PS2MouseState *ps2_mouse_init(void (*update_irq)(void *, int), void *update_arg);
void ps2_write_mouse(void *, int val);
void ps2_write_keyboard(void *, int val);
uint32_t ps2_read_data(void *);
void ps2_queue(void *, int b);
void ps2_keyboard_set_translation(void *opaque, int mode);

void ps2_put_keycode(PS2KbdState *s, int is_down, int keycode);
void ps2_mouse_event(PS2MouseState *s,
                     int dx, int dy, int dz, int buttons_state);

typedef struct KBDState KBDState;

uint32_t kbd_read_status(void *opaque, uint32_t addr);
void kbd_write_command(void *opaque, uint32_t addr, uint32_t val);
uint32_t kbd_read_data(void *opaque, uint32_t addr);
void kbd_write_data(void *opaque, uint32_t addr, uint32_t val);
void kbd_step(void *opaque);

KBDState *i8042_init(PS2KbdState **pkbd,
                     PS2MouseState **pmouse,
                     int kbd_irq, int mouse_irq,
		     void *pic,
                     void (*set_irq)(void *pic, int irq, int level),
                     void *sys,
                     void (*system_reset_request)(void *sys));

#endif /* I8042_H */
