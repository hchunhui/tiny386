#include <stdio.h>
#include <string.h>
#include "../pc.h"

#include <time.h>
uint32_t get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}

void *bigmalloc(size_t size)
{
	return malloc(size);
}

int load_rom(void *phys_mem, const char *file, uword addr, int backward)
{
	FILE *fp = fopen(file, "rb");
	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	fprintf(stderr, "%s len %d\n", file, len);
	rewind(fp);
	if (backward)
		fread(phys_mem + addr - len, 1, len, fp);
	else
		fread(phys_mem + addr, 1, len, fp);
	fclose(fp);
	return len;
}

typedef struct {
	PC *pc;
	u8 *fb;
} Console;

Console *console_init(int width, int height)
{
	Console *c = malloc(sizeof(Console));
	c->fb = bigmalloc(width * height * 4);
	return c;
}

static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
}

static void poll(void *opaque)
{
}

PCConfig *wasm_prepare(const char *inifile)
{
	PCConfig *conf = malloc(sizeof(PCConfig));
	memset(conf, 0, sizeof(PCConfig));
	conf->linuxstart = "linuxstart.bin";
	conf->bios = "bios.bin";
	conf->vga_bios = "vgabios.bin";
	conf->mem_size = 8 * 1024 * 1024;
	conf->vga_mem_size = 256 * 1024;
	conf->width = 720;
	conf->height = 480;
	conf->cpu_gen = 4;
	conf->fpu = 0;

	int err = ini_parse(inifile, parse_conf_ini, conf);
	if (err) {
		printf("error %d\n", err);
		return NULL;
	}

	void __filestore_fetch(const char *);
#define FETCH(fld) \
	do {if (conf->fld && conf->fld[0]) __filestore_fetch(conf->fld);} while(0)
	FETCH(linuxstart);
	FETCH(kernel);
	FETCH(initrd);
	FETCH(bios);
	FETCH(vga_bios);
	for (int i = 0; i < 4; i++)
		FETCH(disks[i]);
	for (int i = 0; i < 2; i++)
		FETCH(fdd[i]);
#undef FETCH
	return conf;
}

Console *wasm_init(PCConfig *conf)
{
	Console *console = console_init(conf->width, conf->height);
	PC *pc = pc_new(redraw, poll, console, console->fb, conf);
	console->pc = pc;

	load_bios_and_reset(pc);
	pc->boot_start_time = get_uticks();
	return console;
}

extern int fake_nsecs;
int wasm_loop(Console *console)
{
	PC *pc = console->pc;

	for (int i = 0; i < 64 && pc->shutdown_state != 8; i++) {
		pc_step(pc);
	}

	if (pc->shutdown_state != 8) {
		return 1;
	}
	return 0;
}

u8 *wasm_getfb(Console *console)
{
	return console->fb;
}

void wasm_send_mouse(Console *console, int x, int y, int z, int btn)
{
	ps2_mouse_event(console->pc->mouse, x, y, z, btn);
}

void wasm_send_kbd(Console *console, int keypress, int keycode)
{
	ps2_put_keycode(console->pc->kbd, keypress, keycode);
}

#define SAMPLE_NUM 256
static double audiobuf[SAMPLE_NUM * 2];
static int16_t buf[SAMPLE_NUM * 2];
int wasm_getaudiolen(Console *console) // sample num
{
	return SAMPLE_NUM;
}

double *wasm_getaudio(Console *console)
{
	memset(buf, 0, SAMPLE_NUM * 2 * 2);
	mixer_callback(console->pc, (void *) buf, SAMPLE_NUM * 2 * 2);
	for (int i = 0; i < SAMPLE_NUM; i++) {
		// left
		audiobuf[i] = buf[i * 2] / 32768.0f;
	}
	int off = SAMPLE_NUM;
	for (int i = 0; i < SAMPLE_NUM; i++) {
		// right
		audiobuf[off + i] = buf[i * 2 + 1] / 32768.0f;
	}
	return audiobuf;
}
