#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "pc.h"
#include "osd/osd.h"

#define CNFG_IMPLEMENTATION
#include "CNFG.h"

#define CNFA_IMPLEMENTATION
#include "CNFA.h"

// platform HAL implementation
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
	void *fb;
	int cnfgret;
	PC *pc;
	OSD *osd;
	bool osd_enabled;
	int lastx, lasty, relx, rely, dz;
	int mbtn;
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
	s->fb = bigmalloc(s->width * s->height * 4);
	s->cnfgret = 1;
	CNFGSetup("tiny386 - use ctrl + ] to grab/ungrab", s->width, s->height);
	osd_attach_console(s->osd, s);
	s->lastx = -1;
	s->lasty = -1;
	s->relx = 0;
	s->rely = 0;
	s->dz = 0;
	s->mbtn = 0;
	return s;
}

//
static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	if (s->osd_enabled)
		osd_render(s->osd, s->fb,
			   s->width, s->height, s->width * 4);
	CNFGUpdateScreenWithBitmap(s->fb, s->width, s->height);
}

static void *g_opaque;
static void cnfgpoll(void *opaque)
{
	Console *s = opaque;
	g_opaque = s;
	s->cnfgret = CNFGHandleInput();
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

void HandleKey(int cnfgkeycode, int bDown)
{
	Console *s = g_opaque;
	int keycode = translate_key(cnfgkeycode);
	if (keycode <= KEYCODE_MAX)
		key_pressed[keycode] = bDown;

	if (bDown) {
		if (keycode == 0x1a && key_pressed[0x1d]) {
			s->osd_enabled = !s->osd_enabled;
			osd_attach_emulink(s->osd, s->pc->emulink);
			osd_attach_ide(s->osd, s->pc->ide, s->pc->ide2);
			s->pc->full_update = s->osd_enabled ? 1 : 2;
			return;
		}
		if (keycode == 0x1b && key_pressed[0x1d]) {
			static int en;
			en ^= 1;
			CNFGConfineMouse(en);
			CNFGSetCursor(en ? CNFG_CURSOR_HIDDEN : CNFG_CURSOR_ARROW);
			return;
		}
	}

	if (keycode) {
		if (s->osd_enabled)
			osd_handle_key(s->osd, keycode, bDown);
		else
			ps2_put_keycode(s->pc->kbd, bDown, keycode);
	}
}

static void mouse_common(int rel, int x, int y, int mask, int down)
{
	Console *s = g_opaque;
	update_mouse(s, rel, x, y, mask);
	if (s->osd_enabled) {
		if (down >= 0)
			osd_handle_mouse_button(s->osd,	s->lastx, s->lasty,
						down, 1 /* XXX */);
		else
			osd_handle_mouse_motion(s->osd, s->lastx, s->lasty);
	} else
		ps2_mouse_event(s->pc->mouse, s->relx, s->rely,
				s->dz, s->mbtn);
}

void HandleButton(int x, int y, int button, int bDown)
{
	mouse_common(0, x, y, bDown ? 1 << (button - 1) : 0, !!bDown);
}

void HandleMotion(int x, int y, int mask)
{
	mouse_common(0, x, y, mask, -1);
}

void HandleButtonRel(int x, int y, int button, int bDown)
{
	mouse_common(1, x, y, bDown ? 1 << (button - 1) : 0, !!bDown);
}

void HandleMotionRel(int x, int y, int mask)
{
	mouse_common(1, x, y, mask, -1);
}

int HandleDestroy()
{
	return 0;
}

void cnfa_callback(struct CNFADriver * sd, short * out, short * in, int framesp, int framesr)
{
	PC *pc = sd->opaque;
	int channels = sd->channelsPlay;
	memset(out, 0, framesp * channels * 2);
	mixer_callback(pc, (void *) out, framesp * channels * 2);
}

void console_set_audio(Console *console)
{
	struct CNFADriver * cnfa;
	cnfa = CNFAInit(
		NULL, //You can select a plaback driver, or use NULL for default.
		"tiny386_audio", cnfa_callback,
		44100, //Requested samplerate for playback
		0, //Requested samplerate for recording
		2, //Number of playback channels.
		0, //Number of record channels.
		1024, //Buffer size in frames.
		0, 0, console->pc);
	if (!cnfa)
		abort();
}

#undef main
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
		fprintf(stderr, "error %d\n", err);
		return err;
	}

	Console *console = console_init(conf.width, conf.height);
	PC *pc = pc_new(redraw, cnfgpoll, console, console->fb, &conf);
	console->pc = pc;
	console_set_audio(console);
	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8 && console->cnfgret;) {
		pc_step(pc);
	}
	return 0;
}
