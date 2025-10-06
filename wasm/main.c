#include "../main.c"

struct pcconfig *wasm_prepare(void)
{
	const char *inifile = "config.ini";
	struct pcconfig *conf = malloc(sizeof(struct pcconfig));
	memset(conf, 0, sizeof(struct pcconfig));
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

Console *wasm_init(struct pcconfig *conf)
{
	Console *console = console_init(conf->width, conf->height);
	u8 *fb = console_get_fb(console);
	PC *pc = pc_new(redraw, poll, console, fb, conf);
	console->pc = pc;
	console_set_audio(console);

	load_bios_and_reset(pc);
	pc->boot_start_time = get_uticks();
	return console;
}

int wasm_loop(Console *console)
{
	PC *pc = console->pc;
	if (pc->shutdown_state != 8) {
		pc_step(pc);
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
