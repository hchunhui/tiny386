#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
SOCKET fd;
#else
#include <arpa/inet.h>
int fd;
#endif

#define CNFG_IMPLEMENTATION
#include "CNFG.h"

void ps2_put_keycode(void *s, int is_down, int keycode)
{
	uint8_t data[1];
	data[0] = keycode & 0x7f;
	if (!is_down)
		data[0] |= 0x80;
	printf("put %x\n", data[0]);
	send(fd, (char *) data, 1, 0);
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
	int ret = send(fd, (char *) data, 5, 0);
	assert(ret == 5);
}

typedef struct {
	void *kbd;
	void *mouse;
} PC;

typedef struct {
	int width, height;
	PC pc0, *pc;

	int cnfgret;
	int lastx, lasty, relx, rely, dz;
	int mbtn;
} Console;
#define BPP 32

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	s->width = width;
	s->height = height;
	s->cnfgret = 1;
	CNFGSetup("tiny386 - use ctrl + ] to grab/ungrab", s->width, s->height);
	s->lastx = -1;
	s->lasty = -1;
	s->relx = 0;
	s->rely = 0;
	s->dz = 0;
	s->mbtn = 0;

	s->pc = &(s->pc0);
	return s;
}

static void update_mouse(Console *s, int rel, int x, int y, int cnfgmask)
{
	if (rel) {
		s->relx = x;
		s->rely = y;
		s->lastx += x;
		s->lasty += y;
		if (s->lastx < 0) s->lastx = 0;
		if (s->lasty < 0) s->lasty = 0;
		if (s->lastx > 2048) s->lastx = 2048;
		if (s->lasty > 2048) s->lasty = 2048;
	} else {
		if (s->lastx < 0 || s->lasty < 0) {
			s->lastx = x;
			s->lasty = y;
		}
		s->relx = x - s->lastx;
		s->rely = y - s->lasty;
		s->lastx = x;
		s->lasty = y;
	}

	s->mbtn = 0;
	if (cnfgmask & 1) s->mbtn |= 1;
	if (cnfgmask & 2) s->mbtn |= 4;
	if (cnfgmask & 4) s->mbtn |= 2;
	s->dz = 0;
	if (cnfgmask & 8) s->dz = -1;
	if (cnfgmask & 16) s->dz = 1;
}

static int translate_key(int cnfgkeycode)
{
#ifdef _WIN32
	return CNFGLastScancode;
#else
	int keycode = CNFGLastScancode;
	if (keycode < 9) {
		keycode = 0;
	} else if (keycode < 127 + 8) {
		keycode -= 8;
	} else {
		keycode = 0;
	}
	return keycode;
#endif	
}

#define KEYCODE_MAX 127
static uint8_t key_pressed[KEYCODE_MAX + 1];
static void *g_opaque;

void HandleKey(int cnfgkeycode, int bDown)
{
	Console *s = g_opaque;
	int keycode = translate_key(cnfgkeycode);
	if (keycode <= KEYCODE_MAX)
		key_pressed[keycode] = bDown;

	if (bDown) {
		if (keycode == 0x1b && key_pressed[0x1d]) {
			static int en;
			en ^= 1;
			CNFGConfineMouse(en);
			// TODO: confine keyboard
			CNFGSetCursor(en ? CNFG_CURSOR_HIDDEN : CNFG_CURSOR_ARROW);
			return;
		}
	}

	if (keycode) {
		ps2_put_keycode(s->pc->kbd, bDown, keycode);
	}
}

static void mouse_common(int rel, int x, int y, int mask)
{
	Console *s = g_opaque;
	update_mouse(s, rel, x, y, mask);

	static int x0, y0;
	x0 += s->relx;
	y0 += s->rely;

	static uint32_t last = 0;
	uint32_t now = get_uticks();
	if (last == 0 || after_eq(now, last)) {
		last = now + 24000;
		ps2_mouse_event(s->pc->mouse, x0, y0, 0, s->mbtn);
		x0 = 0;
		y0 = 0;
	}
}

void HandleButton(int x, int y, int button, int bDown)
{
	mouse_common(0, x, y, bDown ? 1 << (button - 1) : 0);
}

void HandleMotion(int x, int y, int mask)
{
	mouse_common(0, x, y, mask);
}

void HandleButtonRel(int x, int y, int button, int bDown)
{
	mouse_common(1, x, y, bDown ? 1 << (button - 1) : 0);
}

void HandleMotionRel(int x, int y, int mask)
{
	mouse_common(1, x, y, mask);
}

int HandleDestroy()
{
	return 0;
}

#undef main
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
	g_opaque = console;
	CNFGClearFrame();
	CNFGSwapBuffers();
	for (;console->cnfgret;) {
		console->cnfgret = CNFGHandleInput();
		usleep(10000);
	}
	return 0;
}
