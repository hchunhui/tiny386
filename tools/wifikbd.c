#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
SOCKET fd;
#else
#include <arpa/inet.h>
int fd;
#endif

void ps2_put_keycode(void *s, int is_down, int keycode)
{
	uint8_t data[1];
	data[0] = keycode & 0x7f;
	if (!is_down)
		data[0] |= 0x80;
	printf("put %x\n", data[0]);
	send(fd, data, 1, 0);
}

static uint8_t t(int x)
{
	uint8_t res = x;
	if (x > 127)
		res = 127;
	if (x < -127)
		res = -127;
	return res;
}

void ps2_mouse_event(void *s,
		     int dx, int dy, int dz, int buttons_state)
{
	uint8_t data[5];
	data[0] = 0;
	data[1] = t(dx);
	data[2] = t(dy);
	data[3] = t(dz);
	data[4] = buttons_state;
	int ret = send(fd, data, 5, 0);
	assert(ret == 5);
}

#include "SDL.h"
typedef struct {
	void *kbd;
	void *mouse;
} PC;

typedef struct {
	int width, height;
	SDL_Surface *screen;
	PC pc0, *pc;
} Console;
#define BPP 32

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	s->width = width;
	s->height = height;
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
	s->screen = SDL_SetVideoMode(s->width, s->height, BPP, 0);
	s->pc = &(s->pc0);
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY*5,
			    SDL_DEFAULT_REPEAT_INTERVAL*5);
	SDL_WM_SetCaption("tiny386 - use ctrl + ] to grab/ungrab", NULL);
	return s;
}

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
	int keycode;
	keycode = ev->keysym.scancode;
	if (keycode == 0) {
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
		default: printf("unknown %x %d\n", sym, sym); return 0;
		}
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
			usleep(100);
			ps2_put_keycode(pc->kbd, 0, keycode);
		} else
#endif
		{
			keypress = (ev->type == SDL_KEYDOWN);
			if (keycode == 0x1b && keypress &&
			    (key_pressed[0x1d])) {
				static int en;
				en ^= 1;
				printf("en=%d\n", en);
				SDL_ShowCursor(en ? SDL_DISABLE : SDL_ENABLE);
				SDL_WM_GrabInput(en ? SDL_GRAB_ON : SDL_GRAB_OFF);
				return;
			}
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

#include <time.h>
static uint32_t get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}

static int after_eq(uint32_t a, uint32_t b)
{
	return (a - b) < (1u << 31);
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
	static int x0, y0;
	x0 += x;
	y0 += y;

	static uint32_t last = 0;
	uint32_t now = get_uticks();
	if (last == 0 || after_eq(now, last)) {
		last = now + 24000;
		sdl_send_mouse_event(pc, x0, y0, 0, ev->motion.state, is_absolute);
		x0 = 0;
		y0 = 0;
	}
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

int main(int argc, char *argv[])
{
#ifdef _WIN32
	WSADATA Data;
	WSAStartup(MAKEWORD(2, 0), &Data);
#endif
	if (argc != 3)
		return 1;
	int ret;
	struct sockaddr_in addr;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &addr.sin_addr) <= 0) {
		return -2;
	}

	if ((ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr))) < 0) {
		return -1;
	}

	Console *console = console_init(640, 480);
	for (;;) {
		poll(console);
		usleep(100);
	}
	return 0;
}
