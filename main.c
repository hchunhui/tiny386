//#define USEKVM
//#define LINUXSTART
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "i386.h"
#include "i8259.h"
#include "i8254.h"
#include "ide.h"
#include "vga.h"
#include "i8042.h"
#include "misc.h"
#include "adlib.h"

#include <time.h>
static uint32_t get_uticks()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint32_t) ts.tv_sec * 1000000 +
	    (uint32_t) ts.tv_nsec / 1000);
}

#ifdef USEKVM
#include "kvm.h"
typedef CPUKVM CPU;
#else
typedef CPUI386 CPU;
#endif

typedef struct {
	CPU *cpu;
	PicState2 *pic;
	PITState *pit;
	U8250 *serial;
	CMOS *cmos;
	IDEIFState *ide, *ide2;
	VGAState *vga;
	FBDevice *fb_dev;
	char *phys_mem;
	long phys_mem_size;
	char *vga_mem;
	int64_t boot_start_time;

	SimpleFBDrawFunc *redraw;
	void *redraw_data;
	void (*poll)(void *);

	KBDState *i8042;
	PS2KbdState *kbd;
	PS2MouseState *mouse;
	AdlibState *adlib;

	u8 port92;
	int shutdown_state;
	int reset_request;
} PC;

u8 pc_io_read(void *o, int addr)
{
	PC *pc = o;
	u8 val;

	switch(addr) {
	case 0x20: case 0x21: case 0xa0: case 0xa1:
		val = i8259_ioport_read(pc->pic, addr);
		return val;
#ifdef LINUXSTART
	case 0x3f8: case 0x3f9: case 0x3fa: case 0x3fb:
	case 0x3fc: case 0x3fd: case 0x3fe: case 0x3ff:
		val = u8250_reg_read(pc->serial, addr - 0x3f8);
		return val;
#endif
	case 0x2f8: case 0x2f9: case 0x2fa: case 0x2fb:
	case 0x2fc: case 0x2fd: case 0x2fe: case 0x2ff:
	case 0x2e8: case 0x2e9: case 0x2ea: case 0x2eb:
	case 0x2ec: case 0x2ed: case 0x2ee: case 0x2ef:
	case 0x3e8: case 0x3e9: case 0x3ea: case 0x3eb:
	case 0x3ec: case 0x3ed: case 0x3ee: case 0x3ef:
		return 0;
	case 0x40: case 0x41: case 0x42: case 0x43:
		val = i8254_ioport_read(pc->pit, addr);
		return val;
	case 0x70: case 0x71:
		val = cmos_ioport_read(pc->cmos, addr);
		return val;
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		val = ide_ioport_read(pc->ide, addr - 0x1f0);
		return val;
	case 0x170: case 0x171: case 0x172: case 0x173:
	case 0x174: case 0x175: case 0x176: case 0x177:
		val = ide_ioport_read(pc->ide2, addr - 0x170);
		return val;
	case 0x3f6:
		val = ide_status_read(pc->ide);
		return val;
	case 0x376:
		val = ide_status_read(pc->ide2);
		return val;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de: case 0x3df:
		val = vga_ioport_read(pc->vga, addr);
		return val;
	case 0x92:
		return pc->port92;
	case 0x60:
		val = kbd_read_data(pc->i8042, addr);
		return val;
	case 0x64:
		val = kbd_read_status(pc->i8042, addr);
		return val;
	case 0x61:
		return 0xff;
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a:
		return adlib_read(pc->adlib, addr);
	default:
		fprintf(stderr, "in 0x%x <= 0x%x\n", addr, 0xff);
		return 0xff;
	}
}

u16 pc_io_read16(void *o, int addr)
{
	PC *pc = o;
	u16 val;

	switch(addr) {
	case 0x1f0:
		val = ide_data_readw(pc->ide);
		return val;
	case 0x170:
		val = ide_data_readw(pc->ide2);
		return val;
	default:
		fprintf(stderr, "inw 0x%x <= 0x%x\n", addr, 0xffff);
		return 0xffff;
	}
}

u32 pc_io_read32(void *o, int addr)
{
	PC *pc = o;
	if (addr == 0x3cc)
		return (get_uticks() - pc->boot_start_time) / 1000;
	fprintf(stderr, "ind 0x%x <= 0x%x\n", addr, 0xffffffff);
	return 0xffffffff;
}

void pc_io_write(void *o, int addr, u8 val)
{
	PC *pc = o;
	switch(addr) {
	case 0x20: case 0x21: case 0xa0: case 0xa1:
		i8259_ioport_write(pc->pic, addr, val);
		return;
	case 0x3f8: case 0x3f9: case 0x3fa: case 0x3fb:
	case 0x3fc: case 0x3fd: case 0x3fe: case 0x3ff:
		u8250_reg_write(pc->serial, addr - 0x3f8, val);
		return;
	case 0x2f8: case 0x2f9: case 0x2fa: case 0x2fb:
	case 0x2fc: case 0x2fd: case 0x2fe: case 0x2ff:
	case 0x2e8: case 0x2e9: case 0x2ea: case 0x2eb:
	case 0x2ec: case 0x2ed: case 0x2ee: case 0x2ef:
	case 0x3e8: case 0x3e9: case 0x3ea: case 0x3eb:
	case 0x3ec: case 0x3ed: case 0x3ee: case 0x3ef:
		return;
	case 0x80:
		return;
	case 0x40: case 0x41: case 0x42: case 0x43:
		i8254_ioport_write(pc->pit, addr, val);
		return;
	case 0x70: case 0x71:
		cmos_ioport_write(pc->cmos, addr, val);
		return;
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		ide_ioport_write(pc->ide, addr - 0x1f0, val);
		return;
	case 0x170: case 0x171: case 0x172: case 0x173:
	case 0x174: case 0x175: case 0x176: case 0x177:
		ide_ioport_write(pc->ide2, addr - 0x170, val);
		return;
	case 0x3f6:
		ide_cmd_write(pc->ide, val);
		return;
	case 0x376:
		ide_cmd_write(pc->ide2, val);
		return;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de: case 0x3df:
		vga_ioport_write(pc->vga, addr, val);
		return;
	case 0x402:
		putchar(val);
		fflush(stdout);
		return;
	case 0x92:
		pc->port92 = val;
		return;
	case 0x60:
		kbd_write_data(pc->i8042, addr, val);
		return;
	case 0x64:
		kbd_write_command(pc->i8042, addr, val);
		return;
	case 0x61:
		return;
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a:
		adlib_write(pc->adlib, addr, val);
		return;
	case 0x8900:
		switch (val) {
		case 'S': if (pc->shutdown_state == 0) pc->shutdown_state = 1; break;
		case 'h': if (pc->shutdown_state == 1) pc->shutdown_state = 2; break;
		case 'u': if (pc->shutdown_state == 2) pc->shutdown_state = 3; break;
		case 't': if (pc->shutdown_state == 3) pc->shutdown_state = 4; break;
		case 'd': if (pc->shutdown_state == 4) pc->shutdown_state = 5; break;
		case 'o': if (pc->shutdown_state == 5) pc->shutdown_state = 6; break;
		case 'w': if (pc->shutdown_state == 6) pc->shutdown_state = 7; break;
		case 'n': if (pc->shutdown_state == 7) pc->shutdown_state = 8; break;
		default : pc->shutdown_state = 0; break;
		}
		return;
	default:
		fprintf(stderr, "out 0x%x => 0x%x\n", val, addr);
		return;
	}
}

void pc_io_write16(void *o, int addr, u16 val)
{
	PC *pc = o;
	switch(addr) {
	case 0x1f0:
		ide_data_writew(pc->ide, val);
		return;
	case 0x170:
		ide_data_writew(pc->ide2, val);
		return;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de:
		vga_ioport_write(pc->vga, addr, val & 0xff);
		vga_ioport_write(pc->vga, addr + 1, (val >> 8) & 0xff);
		return;
	default:
		fprintf(stderr, "outw 0x%x => 0x%x\n", val, addr);
		return;
	}
}

void pc_io_write32(void *o, int addr, u32 val)
{
	fprintf(stderr, "outd 0x%x => 0x%x\n", val, addr);
}


static void load_bios(PC *pc);

void pc_step(PC *pc)
{
#ifndef USEKVM
	if (pc->reset_request) {
		pc->reset_request = 0;
		load_bios(pc);
		cpui386_reset(pc->cpu);
	}
#endif
	int refresh = vga_step(pc->vga);
	i8254_update_irq(pc->pit);
	cmos_update_irq(pc->cmos);
#ifdef LINUXSTART
	u8250_update(pc->serial);
#endif
	pc->poll(pc->redraw_data);
	if (refresh) {
		pc->fb_dev->refresh(pc->fb_dev, pc->redraw, pc->redraw_data);
	}
#ifdef USEKVM
	cpukvm_step(pc->cpu, 4096);
#else
	cpui386_step(pc->cpu, 1024);
#endif
}

static void raise_irq(void *o, PicState2 *s)
{
	CPU *cpu = o;
	cpu->intr = true;
}

static int read_irq(void *o)
{
	PicState2 *s = o;
	return i8259_read_irq(s);
}

static void set_irq(void *o, int irq, int level)
{
	PicState2 *s = o;
	return i8259_set_irq(s, irq, level);
}

static u8 iomem_read8(void *iomem, uword addr)
{
	PC *pc = iomem;
	return vga_mem_read(pc->vga, addr - 0xa0000);
}

static void iomem_write8(void *iomem, uword addr, u8 val)
{
	PC *pc = iomem;
	vga_mem_write(pc->vga, addr - 0xa0000, val);
}

static u16 iomem_read16(void *iomem, uword addr)
{
	return iomem_read8(iomem, addr) |
		((u16) iomem_read8(iomem, addr + 1) << 8);
}

static void iomem_write16(void *iomem, uword addr, u16 val)
{
	iomem_write8(iomem, addr, val);
	iomem_write8(iomem, addr + 1, val >> 8);
}

static u32 iomem_read32(void *iomem, uword addr)
{
	return iomem_read16(iomem, addr) |
		((u32) iomem_read16(iomem, addr + 2) << 16);
}

static void iomem_write32(void *iomem, uword addr, u32 val)
{
	iomem_write16(iomem, addr, val);
	iomem_write16(iomem, addr + 2, val >> 16);
}

static void pc_reset_request(void *p)
{
	PC *pc = p;
	pc->reset_request = 1;
}

PC *pc_new(SimpleFBDrawFunc *redraw, void (*poll)(void *), void *redraw_data, char **disks)
{
	PC *pc = malloc(sizeof(PC));
	long mem_size = 16 * 1024 * 1024;
#ifdef USEKVM
	char *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

#else
	char *mem = malloc(mem_size);
#endif
	memset(mem, 0, mem_size);
#ifdef USEKVM
	pc->cpu = cpukvm_new(mem, mem_size);
#else
	pc->cpu = cpui386_new(mem, mem_size);
#endif

	pc->pic = i8259_init(raise_irq, pc->cpu);
	pc->cpu->pic = pc->pic;
	pc->cpu->pic_read_irq = read_irq;

	pc->pit = i8254_init(0, pc->pic, set_irq);
	pc->serial = u8250_init(4, pc->pic, set_irq);
	pc->cmos = cmos_init(mem_size, 8, pc->pic, set_irq);
	pc->ide = ide_allocate(14, pc->pic, set_irq);
	pc->ide2 = ide_allocate(15, pc->pic, set_irq);
	if (disks) {
		for (int i = 0; disks[i] && i < 4; i++) {
			if (i < 2) {
				int ret = ide_attach(pc->ide, i, disks[i]);
				assert(ret == 0);
			} else {
				int ret = ide_attach(pc->ide2, i - 2, disks[i]);
				assert(ret == 0);
			}
		}
	}

	pc->phys_mem = mem;
	pc->phys_mem_size = mem_size;

	pc->cpu->io = pc;
	pc->cpu->io_read8 = pc_io_read;
	pc->cpu->io_write8 = pc_io_write;
	pc->cpu->io_read16 = pc_io_read16;
	pc->cpu->io_write16 = pc_io_write16;
	pc->cpu->io_read32 = pc_io_read32;
	pc->cpu->io_write32 = pc_io_write32;

	pc->boot_start_time = 0;

	FBDevice *fb_dev = malloc(sizeof(FBDevice));
	memset(fb_dev, 0, sizeof(FBDevice));
	pc->vga_mem = malloc(256 * 1024);
	memset(pc->vga_mem, 0, 256 * 1024);
	pc->vga = vga_init(fb_dev, 720, 480, NULL, 0, pc->vga_mem);
	pc->cpu->iomem = pc;
	pc->cpu->iomem_read8 = iomem_read8;
	pc->cpu->iomem_write8 = iomem_write8;
	pc->cpu->iomem_read16 = iomem_read16;
	pc->cpu->iomem_write16 = iomem_write16;
	pc->cpu->iomem_read32 = iomem_read32;
	pc->cpu->iomem_write32 = iomem_write32;

	pc->fb_dev = fb_dev;
	pc->redraw = redraw;
	pc->redraw_data = redraw_data;
	pc->poll = poll;

	pc->i8042 = i8042_init(&(pc->kbd), &(pc->mouse),
			       1, 12, pc->pic, set_irq,
			       pc, pc_reset_request);
	pc->adlib = adlib_new();

	pc->port92 = 0x2;
	pc->shutdown_state = 0;
	pc->reset_request = 0;
	return pc;
}

static int load(PC *pc, const char *file, uword addr)
{
	FILE *fp = fopen(file, "r");
	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	fprintf(stderr, "%s len %d\n", file, len);
	rewind(fp);
	fread(pc->phys_mem + addr, 1, len, fp);
	fclose(fp);
	return len;
}

#ifndef NOSDL
#include "SDL.h"
typedef struct {
	int width, height;
	SDL_Surface *screen;
	PC *pc;
} Console;

Console *console_init()
{
	Console *s = malloc(sizeof(Console));
	s->width = 720;
	s->height = 480;
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
	s->screen = SDL_SetVideoMode(s->width, s->height, 32, 0);
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY,
			    SDL_DEFAULT_REPEAT_INTERVAL);
	return s;
}

static void redraw(FBDevice *fb_dev, void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	memcpy(s->screen->pixels, fb_dev->fb_data, s->width * s->height * 4);
	SDL_Flip(s->screen);
	SDL_PumpEvents();
}

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
	int keycode;
	keycode = ev->keysym.scancode;
	if (keycode < 9) {
		keycode = 0;
	} else if (keycode < 127 + 8) {
		keycode -= 8;
	} else {
		keycode = 0;
	}
	return keycode;
}

/* release all pressed keys */
#define KEYCODE_MAX 127
static uint8_t key_pressed[KEYCODE_MAX + 1];

static void sdl_reset_keys(PC *pc)
{
	int i;
	for(i = 1; i <= KEYCODE_MAX; i++) {
		if (key_pressed[i]) {
			ps2_put_keycode(pc->kbd, 0, i);
			key_pressed[i] = 0;
		}
	}
}

static void sdl_handle_key_event(const SDL_KeyboardEvent *ev, PC *pc)
{
	int keycode, keypress;

	keycode = sdl_get_keycode(ev);
	if (keycode) {
		if (keycode == 0x3a || keycode ==0x45) {
			/* SDL does not generate key up for numlock & caps lock */
			ps2_put_keycode(pc->kbd, 1, keycode);
			ps2_put_keycode(pc->kbd, 0, keycode);
		} else {
			keypress = (ev->type == SDL_KEYDOWN);
			if (keycode <= KEYCODE_MAX)
				key_pressed[keycode] = keypress;
			ps2_put_keycode(pc->kbd, keypress, keycode);
		}
	} else if (ev->type == SDL_KEYUP) {
		/* workaround to reset the keyboard state (used when changing
		   desktop with ctrl-alt-x on Linux) */
		sdl_reset_keys(pc);
	}
}

static void sdl_send_mouse_event(PC *pc, int x1, int y1,
                                 int dz, int state, bool is_absolute)
{
	int buttons, x, y;

	buttons = 0;
	if (state & SDL_BUTTON(SDL_BUTTON_LEFT))
		buttons |= (1 << 0);
	if (state & SDL_BUTTON(SDL_BUTTON_RIGHT))
		buttons |= (1 << 1);
	if (state & SDL_BUTTON(SDL_BUTTON_MIDDLE))
		buttons |= (1 << 2);
	if (is_absolute) {
		x = 0;//(x1 * 32768) / screen_width;
		y = 0;//(y1 * 32768) / screen_height;
	} else {
		x = x1;
		y = y1;
	}
	ps2_mouse_event(pc->mouse, x, y, dz, buttons);
}

static void sdl_handle_mouse_motion_event(const SDL_Event *ev, PC *pc)
{
	bool is_absolute = 0; //vm_mouse_is_absolute(m);
	int x, y;
	if (is_absolute) {
		x = ev->motion.x;
		y = ev->motion.y;
	} else {
		x = ev->motion.xrel;
		y = ev->motion.yrel;
	}
	sdl_send_mouse_event(pc, x, y, 0, ev->motion.state, is_absolute);
}

static void sdl_handle_mouse_button_event(const SDL_Event *ev, PC *pc)
{
	bool is_absolute = 0; //vm_mouse_is_absolute(m);
	int state, dz;

	dz = 0;
	if (ev->type == SDL_MOUSEBUTTONDOWN) {
		if (ev->button.button == SDL_BUTTON_WHEELUP) {
			dz = -1;
		} else if (ev->button.button == SDL_BUTTON_WHEELDOWN) {
			dz = 1;
		}
	}

	state = SDL_GetMouseState(NULL, NULL);
	/* just in case */
	if (ev->type == SDL_MOUSEBUTTONDOWN)
		state |= SDL_BUTTON(ev->button.button);
	else
		state &= ~SDL_BUTTON(ev->button.button);

	if (is_absolute) {
		sdl_send_mouse_event(pc, ev->button.x, ev->button.y,
				     dz, state, is_absolute);
	} else {
		sdl_send_mouse_event(pc, 0, 0, dz, state, is_absolute);
	}
}

static void poll(void *opaque)
{
	Console *s = opaque;
	SDL_Surface *sdl = s->screen;
	SDL_Event ev;

	while (SDL_PollEvent(&ev)) {
		switch (ev.type) {
		case SDL_KEYDOWN:
		case SDL_KEYUP:
			sdl_handle_key_event(&(ev.key), s->pc);
			break;
		case SDL_MOUSEMOTION:
			sdl_handle_mouse_motion_event(&ev, s->pc);
			break;
		case SDL_MOUSEBUTTONDOWN:
		case SDL_MOUSEBUTTONUP:
			sdl_handle_mouse_button_event(&ev, s->pc);
			break;
		case SDL_QUIT:
			exit(0);
		}
	}
}
#else
typedef struct {
	PC *pc;
} Console;

Console *console_init()
{
	return NULL;
}

static void redraw(FBDevice *fb_dev, void *opaque,
		   int x, int y, int w, int h)
{
}

static void poll(void *opaque)
{
}
#endif

#ifdef LINUXSTART
static void load_bios(PC *pc)
{
}

int main(int argc, char *argv[])
{
	const char *vmlinux = "vmlinux.bin";
	Console *console = console_init();
	PC *pc = pc_new(redraw, poll, console, argv + 1);
	if (console)
		console->pc = pc;

	load(pc, "linuxstart.bin", 0x0010000);
	load(pc, vmlinux, 0x00100000);
//	int initrd_size = load(pc, "root.bin", 0x00400000);

	uword start_addr = 0x10000;
	uword cmdline_addr = 0xf800;
	strcpy(pc->cpu->phys_mem + cmdline_addr,
	       "console=ttyS0 root=/dev/hda rw init=/sbin/init notsc=1");

	cpui386_reset_pm(pc->cpu, start_addr);
	pc->cpu->gpr[0] = pc->phys_mem_size;
	pc->cpu->gpr[3] = 0;//initrd_size;
	pc->cpu->gpr[1] = cmdline_addr;

	CaptureKeyboardInput();

	pc->boot_start_time = get_uticks();

	long k = 0;
	for (;;) {
		long last = pc->cpu->cycle;
		pc_step(pc);
		k += pc->cpu->cycle - last;
		if (k >= 4096 * 1) {
			usleep(4000);
			k = 0;
		}
	}

	for (;;) {
		pc_step(pc);
	}
	return 0;
}
#else
static void load_bios(PC *pc)
{
	load(pc, "bios.bin", 0xe0000);
	load(pc, "vgabios.bin", 0xc0000);
}

int main(int argc, char *argv[])
{
	Console *console = console_init();
	PC *pc = pc_new(redraw, poll, console, argv + 1);
	if (console)
		console->pc = pc;

	load_bios(pc);

	SDL_AudioSpec audio_spec = {0};
	audio_spec.freq = 44100;
	audio_spec.format = AUDIO_S16SYS;
	audio_spec.channels = 1;
	audio_spec.samples = 1024;
	audio_spec.callback = adlib_callback;
	audio_spec.userdata = pc->adlib;
	SDL_OpenAudio(&audio_spec, 0);

	pc->boot_start_time = get_uticks();
	long k = 0;
	for (; pc->shutdown_state != 8;) {
		long last = pc->cpu->cycle;
		pc_step(pc);
#ifndef USEKVM
		k += pc->cpu->cycle - last;
		if (k >= 1024) {
//			usleep(4000);
//			usleep(20);
			usleep(4);
			k = 0;
		}
#endif
	}
	return 0;
}
#endif
