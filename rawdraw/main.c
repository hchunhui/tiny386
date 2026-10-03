#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "pc.h"
#include "osd/osd.h"
#include "term.h"

#ifndef ANDROID
#define CNFG_IMPLEMENTATION
#include "CNFG.h"

#define CNFA_IMPLEMENTATION
#include "CNFA.h"
#else /* ANDROID */
#include "CNFGAndroid.h"
#include "android/vkbd.h"
#define VKBD_SCALE 1.5

#define CNFA_IMPLEMENTATION
#include "android/rawdrawandroid/cnfa/CNFA.h"

#define CNFG_IMPLEMENTATION
#define CNFG3D
#include "android/rawdrawandroid/rawdraw/CNFG.h"

void HandleThisWindowTermination()
{
}

void HandleSuspend()
{
}

void HandleResume()
{
}
#endif /* ANDROID */

// platform HAL implementation
#include <time.h>
uint32_t get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}

#ifndef _WIN32
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
#ifdef ANDROID
	uint32_t touch_start, touch_end;
	int touch_btn;
	int btnup_pending;
	int vkbdx, vkbdy;
	bool vkbdinfo[VKBDLAYOUT_LEN];
#endif
} Console;

void console_send_kbd(void *opaque, int keypress, int keycode)
{
	Console *s = opaque;
	ps2_put_keycode(s->pc->kbd, keypress, keycode);
}

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	memset(s, 0, sizeof(Console));
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
#ifndef ANDROID
	CNFGSetup("tiny386 - use ctrl + ] to grab/ungrab", s->width, s->height);
#else
	CNFGSetupFullscreen( "tiny386", 0 );
	HandleWindowTermination = HandleThisWindowTermination;
	s->vkbdx = 1280;
	s->vkbdy = 50;
#endif
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
static void redraw(void *opaque, int x, int y, int w, int h)
{
	Console *s = opaque;
	if (s->osd_enabled)
		osd_render(s->osd, s->fb,
			   s->width, s->height, s->width * 4);
#ifndef ANDROID
	CNFGUpdateScreenWithBitmap(s->fb, s->width, s->height);
#else
	CNFGClearFrame();

	static int vkbd_tex;
	static uint32_t fbk[VKBDLAYOUT_W * VKBDLAYOUT_H];
	if (!vkbd_tex)
		vkbd_tex = CNFGTexImage(NULL, VKBDLAYOUT_W, VKBDLAYOUT_H);
	vkbd_draw(fbk, VKBDLAYOUT_W, VKBDLAYOUT_H, 0, 0, s->vkbdinfo);
	for (int i = 0; i < VKBDLAYOUT_W * VKBDLAYOUT_H; i++)
		fbk[i] = (fbk[i] << 8) | (fbk[i] >> 24);
	glBindTexture(GL_TEXTURE_2D, vkbd_tex);
	glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, VKBDLAYOUT_W, VKBDLAYOUT_H,
			GL_RGBA, GL_UNSIGNED_BYTE, (void *) fbk);
	CNFGBlitTex(vkbd_tex, s->vkbdx, s->vkbdy,
		    VKBDLAYOUT_W * VKBD_SCALE, VKBDLAYOUT_H * VKBD_SCALE);

	static int fb_tex;
	static uint32_t fb2[2000*2000];
	assert(s->width * s->height < 2000 * 2000);
	if (!fb_tex)
		fb_tex = CNFGTexImage(NULL, s->width, s->height);
	uint32_t *fb = s->fb;
	for (int i = 0; i < s->width * s->height; i++)
		fb2[i] = (fb[i] << 8) | 0xff;
	glBindTexture(GL_TEXTURE_2D, fb_tex);
	glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, s->width, s->height,
			GL_RGBA, GL_UNSIGNED_BYTE, (void *) fb2);
	CNFGBlitTex(fb_tex, 0, 0, 1280, 960);

	CNFGSwapBuffers();
#endif
}

static void dummy(void *opaque, int x, int y, int w, int h)
{
}

static void *g_opaque;
static void mouse_common(int rel, int x, int y, int mask, int down);
static void cnfgpoll(void *opaque)
{
	Console *s = opaque;
	g_opaque = s;
#ifdef ANDROID
	if (s->btnup_pending) {
		s->btnup_pending--;
		if (s->btnup_pending == 0)
			mouse_common(1, 0, 0, 0, 0);
	}
#endif
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
	} else if (keycode < 127 + 9) {
		keycode -= 8;
	} else {
		keycode = 0;
	}
	return keycode;
#endif	
}

static void put_key(void *o, unsigned char scan_code, int is_pressed)
{
	ps2_put_keycode(o, is_pressed, scan_code);
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
#ifndef ANDROID
		if (keycode == 0x1b && key_pressed[0x1d]) {
			static int en;
			en ^= 1;
			CNFGConfineMouse(en);
			CNFGSetCursor(en ? CNFG_CURSOR_HIDDEN : CNFG_CURSOR_ARROW);
			return;
		}
#endif
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
#ifdef ANDROID
	Console *s = g_opaque;
	if (x >= s->vkbdx && x < s->vkbdx + VKBDLAYOUT_W * VKBD_SCALE &&
	    y >= s->vkbdy && y < s->vkbdy + VKBDLAYOUT_H * VKBD_SCALE) {
		int i = vkbd_button((x - s->vkbdx) / VKBD_SCALE,
				    (y - s->vkbdy) / VKBD_SCALE);
		if (i >= 0) {
			s->vkbdinfo[i] = bDown;
			int keycode = vkbd_code(i);
			if (keycode) {
				if (s->osd_enabled)
					osd_handle_key(s->osd, keycode, bDown);
				else
					ps2_put_keycode(s->pc->kbd, bDown, keycode);
			}
		}
		return;
	}
	uint32_t t2 = get_uticks();
	if (bDown) {
		s->touch_start = t2;
		if (t2 - s->touch_end < 200000) {
			s->touch_btn = 1;
		} else {
			s->touch_btn = 0;
		}
	}
	if (!bDown) {
		if (t2 - s->touch_start < 200000) {
			mouse_common(1, 0, 0, 1, 1);
			s->btnup_pending = 100;
		} else if (t2 - s->touch_start < 500000) {
			mouse_common(1, 0, 0, 4, 1);
			s->btnup_pending = 100;
		}
		s->touch_start = t2 - 1100000;
		s->touch_end = t2;
	}
	s->lastx = x;
	s->lasty = y;
#else
	mouse_common(0, x, y, bDown ? 1 << (button - 1) : 0, !!bDown);
#endif
}

void HandleMotion(int x, int y, int mask)
{
#ifdef ANDROID
	Console *s = g_opaque;
	if (x >= s->vkbdx && x < s->vkbdx + VKBDLAYOUT_W * VKBD_SCALE &&
	    y >= s->vkbdy && y < s->vkbdy + VKBDLAYOUT_H * VKBD_SCALE)
		return;
	if (abs(s->lastx - x) > 5 || abs(s->lasty - y) > 5)
		s->touch_start = get_uticks() - 1100000;
	if (s->touch_btn)
		s->btnup_pending = 0;
	mouse_common(0, x, y, s->touch_btn, -1);
#else
	mouse_common(0, x, y, mask, -1);
#endif
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

static void cnfa_callback(struct CNFADriver * sd, short * out, short * in, int framesp, int framesr)
{
	PC *pc = sd->opaque;
	int channels = sd->channelsPlay;
	memset(out, 0, framesp * channels * 2);
	mixer_callback(pc, (void *) out, framesp * channels * 2);
}

static bool setup_audio(PC *pc)
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
		0, 0, pc);
	return !!cnfa;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-kvm] [-headless] [-term] inifile\n",
		argv0);
}

#ifndef _WIN32
#include <signal.h>
volatile int g_running = 1;
static void sig_handler(int _)
{
	g_running = 0;
}
static void set_sig_handler()
{
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
}
#else
#define g_running 1
#define set_sig_handler()
#endif

#ifdef ANDROID
#define main main1
#endif

int main(int argc, char *argv[])
{
	PCConfig conf;
	memset(&conf, 0, sizeof(conf));
	conf.mem_size = 8 * 1024 * 1024;
	conf.vga_mem_size = 256 * 1024;
	conf.width = 720;
	conf.height = 480;
	conf.cpu_gen = 4;
	conf.fpu = 0;

	const char *argv1;
	bool enable_kvm = false;
	bool headless = false;
	bool use_term = false;
	if (argc > 1) {
		for (int i = 1; i < argc - 1; i++) {
			if (strcmp(argv[i], "-kvm") == 0)
				enable_kvm = true;
			else if (strcmp(argv[i], "-headless") == 0)
				headless = true;
			else if (strcmp(argv[i], "-term") == 0) {
				headless = true;
				use_term = true;
			} else {
				usage(argv[0]);
				return 1;
			}
		}
		argv1 = argv[argc - 1];
		ne2000_set_config_file(argv1);
	} else {
		usage(argv[0]);
		return 1;
	}

	int err = ini_parse(argv1, parse_conf_ini, &conf);
	if (err) {
		fprintf(stderr, "error %d\n", err);
		return err;
	}
	if (enable_kvm)
		conf.cpu_gen = -1;

	set_sig_handler();

	if (headless) {
		void *fb = bigmalloc(conf.width * conf.height * 4);
		PC *pc = pc_new(dummy, NULL, fb, &conf);
		setup_audio(pc);
		Term *term = NULL;
		if (use_term)
			term = term_init(pc->vga, put_key, pc->kbd);
		load_bios_and_reset(pc);

		pc->boot_start_time = get_uticks();
		for (; g_running && pc->shutdown_state != 8;) {
			pc_step(pc);
			pc_vga_step(pc);
			if (use_term)
				term_step(term);
		}
		return 0;
	}

	Console *console = console_init(conf.width, conf.height);
	PC *pc = pc_new(redraw, console, console->fb, &conf);
	console->pc = pc;
	setup_audio(pc);
	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; g_running && pc->shutdown_state != 8 && console->cnfgret;) {
		pc_step(pc);
		cnfgpoll(console);
		pc_vga_step(pc);
	}
	return 0;
}

#ifdef ANDROID
#undef main
int main(int argc, char *_argv[])
{
	char *argv[3] = {
		_argv[0],
		"tiny386.ini",
		NULL,
	};
	chdir(gapp->activity->externalDataPath);
	int ret = main1(2, argv);
	if (gapp && gapp->activity) {
		ANativeActivity_finish(gapp->activity);
	}
	exit(ret);
	return ret;
}
#endif
