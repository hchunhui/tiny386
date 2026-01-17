#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pc.h"
#include "SDL.h"
#include "osd/osd.h"

#include <time.h>
uint32_t get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}

#ifdef USEKVM
#include <sys/mman.h>
void *bigmalloc(size_t size)
{
	return mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
#else
void *bigmalloc(size_t size)
{
	return malloc(size);
}
#endif

int load_rom(void *phys_mem, const char *file, uword addr, int backward)
{
	FILE *fp = fopen(file, "rb");
	if (fp == NULL) {
		fprintf(stderr, "load_rom: open %s failed: %s\n", file, strerror(errno));
		abort();
	}

	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	fprintf(stderr, "load_rom: %s, len %d\n", file, len);
	rewind(fp);
	if (backward)
		fread(phys_mem + addr - len, 1, len, fp);
	else
		fread(phys_mem + addr, 1, len, fp);
	fclose(fp);
	return len;
}

typedef struct {
	int width, height;
	SDL_Surface *screen;
	PC *pc;
	OSD *osd;
	bool osd_enabled;
} Console;

void console_send_kbd(void *opaque, int keypress, int keycode)
{
	Console *s = opaque;
	ps2_put_keycode(s->pc->kbd, keypress, keycode);
}

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	s->osd = osd_init();
	s->osd_enabled = false;
#ifdef SWAPXY
	s->width = height;
	s->height = width;
#else
	s->width = width;
	s->height = height;
#endif
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
	s->screen = SDL_SetVideoMode(s->width, s->height, BPP, 0);
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY,
			    SDL_DEFAULT_REPEAT_INTERVAL);
	SDL_WM_SetCaption("tiny386 - use ctrl + ] to grab/ungrab", NULL);
	osd_attach_console(s->osd, s);
	return s;
}

static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	if (s->osd_enabled)
		osd_render(s->osd, s->screen->pixels,
			   s->screen->w, s->screen->h, s->screen->pitch);
	SDL_Flip(s->screen);
	SDL_PumpEvents();
}

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
	int keycode = ev->keysym.scancode;
	int sym = ev->keysym.sym;
	switch (sym) {
	case SDLK_UP: return 0x67;
	case SDLK_DOWN: return 0x6c;
	case SDLK_LEFT: return 0x69;
	case SDLK_RIGHT: return 0x6a;
	case SDLK_HOME: return 0x66;
	case SDLK_END: return 0x6b;
	case SDLK_PAGEUP: return 0x68;
	case SDLK_PAGEDOWN: return 0x6d;
	case SDLK_INSERT: return 0x6e;
	case SDLK_DELETE: return 0x6f;
	case SDLK_KP_DIVIDE: return 0x62;
	case SDLK_KP_ENTER: return 0x60;
	case SDLK_RCTRL: return 0x61;
	case SDLK_PAUSE: return 0x77;
	case SDLK_PRINT: return 0x63;
	case SDLK_RALT: return 0x64;
	default: if (keycode == 0) return 0;
	}
#ifndef _WIN32
	if (keycode < 9) {
		keycode = 0;
	} else if (keycode < 127 + 8) {
		keycode -= 8;
	} else {
		keycode = 0;
	}
#endif
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
#if SDL_PATCHLEVEL < 50 /* not sdl12-compat */
		if (keycode == 0x3a || keycode ==0x45) {
			/* SDL does not generate key up for numlock & caps lock */
			ps2_put_keycode(pc->kbd, 1, keycode);
			ps2_put_keycode(pc->kbd, 0, keycode);
		} else
#endif
		{
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
	SDL_Event ev;
	int keycode;

	while (SDL_PollEvent(&ev)) {
		switch (ev.type) {
		case SDL_KEYDOWN:
			keycode = sdl_get_keycode(&(ev.key));
			if (keycode == 0x1a && key_pressed[0x1d]) {
				s->osd_enabled = !s->osd_enabled;
				osd_attach_emulink(s->osd, s->pc->emulink);
				osd_attach_ide(s->osd, s->pc->ide, s->pc->ide2);
				s->pc->full_update = s->osd_enabled ? 1 : 2;
				break;
			}
			if (keycode == 0x1b && key_pressed[0x1d]) {
				static int en;
				en ^= 1;
				SDL_ShowCursor(en ? SDL_DISABLE : SDL_ENABLE);
				SDL_WM_GrabInput(en ? SDL_GRAB_ON : SDL_GRAB_OFF);
				break;
			}
			/* fall through */
		case SDL_KEYUP:
			if (s->osd_enabled)
				osd_handle_key(s->osd, sdl_get_keycode(&(ev.key)),
					       ev.type == SDL_KEYDOWN);
			else
				sdl_handle_key_event(&(ev.key), s->pc);
			break;
		case SDL_MOUSEMOTION:
			if (s->osd_enabled)
				osd_handle_mouse_motion(s->osd,
							ev.motion.x, ev.motion.y);
			else
				sdl_handle_mouse_motion_event(&ev, s->pc);
			break;
		case SDL_MOUSEBUTTONDOWN:
		case SDL_MOUSEBUTTONUP:
			if (s->osd_enabled)
				osd_handle_mouse_button(
					s->osd,
					ev.button.x, ev.button.y,
					ev.type == SDL_MOUSEBUTTONDOWN,
					1 /* XXX */);
			else
				sdl_handle_mouse_button_event(&ev, s->pc);
			break;
		case SDL_QUIT:
			exit(0);
		}
	}
}

void console_set_audio(Console *console)
{
	SDL_AudioSpec audio_spec = {0};
	audio_spec.freq = 44100;
	audio_spec.format = AUDIO_S16SYS;
	audio_spec.channels = 2;
	audio_spec.samples = 512;
	audio_spec.callback = mixer_callback;
	audio_spec.userdata = console->pc;
	SDL_OpenAudio(&audio_spec, 0);
	SDL_PauseAudio(0);
}

u8 *console_get_fb(Console *console)
{
	return console->screen->pixels;
}

int main(int argc, char *argv[])
{
	PCConfig conf;
	memset(&conf, 0, sizeof(conf));
	conf.linuxstart = "linuxstart.bin";
	conf.bios = "bios.bin";
	conf.vga_bios = "vgabios.bin";
	conf.mem_size = 8 * 1024 * 1024;
	conf.vga_mem_size = 256 * 1024;
	conf.width = 720;
	conf.height = 480;
	conf.cpu_gen = 4;
	conf.fpu = 0;

	if (argc != 2)
		return 1;

	int err = ini_parse(argv[1], parse_conf_ini, &conf);
	if (err) {
		printf("error %d\n", err);
		return err;
	}

	Console *console = console_init(conf.width, conf.height);
	u8 *fb = console_get_fb(console);
	PC *pc = pc_new(redraw, poll, console, fb, &conf);
	console->pc = pc;
	console_set_audio(console);
	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8;) {
		pc_step(pc);
	}
	return 0;
}
