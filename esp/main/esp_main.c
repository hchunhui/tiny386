/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include <inttypes.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_psram.h"
#include "esp_partition.h"
#include "driver/uart.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"

#include "../../ini.h"
#include "../../pc.h"
#include "common.h"

//
#include "esp_private/system_internal.h"
uint32_t get_uticks()
{
	return esp_system_get_time();
}

void *psmalloc(long size);
void *fbmalloc(long size);
void *bigmalloc(size_t size)
{
	return psmalloc(size);
}

char *pcram;
long pcram_off;
long pcram_len;
void *pcmalloc(long size)
{
	void *ret = pcram + pcram_off;

	size = (size + 31) / 32 * 32;
	if (pcram_off + size > pcram_len) {
		printf("pcram error %ld %ld %ld\n", size, pcram_off, pcram_len);
		abort();
	}
	pcram_off += size;
	return ret;
}

int load_rom(void *phys_mem, const char *file, uword addr, int backward)
{
	if (file && file[0] == '/') {
		FILE *fp = fopen(file, "rb");
		assert(fp);
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
	const esp_partition_t *part =
		esp_partition_find_first(ESP_PARTITION_TYPE_ANY,
					 ESP_PARTITION_SUBTYPE_ANY,
					 file);
	assert(part);
	int len = part->size;
	fprintf(stderr, "%s len %d\n", file, len);
	if (backward)
		esp_partition_read(part, 0, phys_mem + addr - len, len);
	else
		esp_partition_read(part, 0, phys_mem + addr, len);
	return len;
}

//
EventGroupHandle_t global_event_group;
struct Globals globals;

typedef struct {
	PC *pc;
	u8 *fb1;
	u8 *fb;
} Console;

#define NN 32
Console *console_init(int width, int height)
{
	Console *c = malloc(sizeof(Console));
	c->fb1 = fbmalloc(LCD_WIDTH * LCD_HEIGHT / NN * 2);
	c->fb = bigmalloc(LCD_WIDTH * LCD_HEIGHT * 2);
	return c;
}

void lcd_draw(int x_start, int y_start, int x_end, int y_end, void *src);
static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	for (int i = 0; i < NN; i++) {
		uint16_t *src = (uint16_t *) s->fb;
		src += LCD_WIDTH * LCD_HEIGHT / NN * i;
		memcpy(s->fb1, src, LCD_WIDTH * LCD_HEIGHT / NN * 2);
		lcd_draw(0, LCD_WIDTH / NN * i,
			 LCD_HEIGHT, LCD_WIDTH / NN * (i + 1),
			 s->fb1);
		vga_step(s->pc->vga);
		usleep(900);
	}
}

static void stub(void *opaque)
{
}

static int pc_main(const char *file)
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

	int err = ini_parse(file, parse_conf_ini, &conf);
	if (err) {
		printf("error %d\n", err);
		return err;
	}

	Console *console = console_init(conf.width, conf.height);
	PC *pc = pc_new(redraw, stub, console, console->fb, &conf);
	console->pc = pc;
	globals.pc = pc;
	globals.kbd = pc->kbd;
	globals.mouse = pc->mouse;
	xEventGroupSetBits(global_event_group, BIT0);

	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8;) {
		pc_step(pc);
	}
	return 0;
}

//
static const char *TAG = "esp_main";

void *esp_psram_get(size_t *size);
void vga_task(void *arg);
void i2s_main();
void wifi_main(const char *, const char *);
void storage_init(void);

struct esp_ini_config {
	const char *filename;
	char ssid[16];
	char pass[32];
};

static void i386_task(void *arg)
{
	struct esp_ini_config *config = arg;
	int core_id = esp_cpu_get_core_id();
	fprintf(stderr, "main runs on core %d\n", core_id);
	pc_main(config->filename);
	vTaskDelete(NULL);
}

static char *psram;
static long psram_off;
static long psram_len;
void *psmalloc(long size)
{
	void *ret = psram + psram_off;

	size = (size + 4095) / 4096 * 4096;
	if (psram_off + size > psram_len) {
		fprintf(stderr, "psram error %ld %ld %ld\n", size, psram_off, psram_len);
		abort();
	}
	psram_off += size;
	return ret;
}

void *fbmalloc(long size)
{
	void *fb = (uint8_t *) heap_caps_calloc(1, size, MALLOC_CAP_DMA);
	if (!fb) {
		fprintf(stderr, "fbmalloc error %ld\n", size);
		abort();
	}
	return fb;
}

static int parse_ini(void* user, const char* section,
		     const char* name, const char* value)
{
	struct esp_ini_config *conf = user;
#define SEC(a) (strcmp(section, a) == 0)
#define NAME(a) (strcmp(name, a) == 0)
	if (SEC("esp")) {
		if (NAME("ssid")) {
			if (strlen(value) < 32)
				strcpy(conf->ssid, value);
		} else if (NAME("pass")) {
			if (strlen(value) < 64)
				strcpy(conf->pass, value);
		}
	}
#undef SEC
#undef NAME
	return 1;
}

void app_main(void)
{
	global_event_group = xEventGroupCreate();

#ifdef ESPDEBUG
	uart_config_t uart_config = {
		.baud_rate = 115200,
		.data_bits = UART_DATA_8_BITS,
		.parity	= UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
		.source_clk = UART_SCLK_DEFAULT,
	};

	uart_param_config(UART_NUM_0, &uart_config);
	if (uart_driver_install(UART_NUM_0, 2 * 1024, 0, 0, NULL, 0) != ESP_OK) {
		assert(false);
	}
#endif

	i2s_main();
	storage_init();

	esp_psram_init();
#ifndef PSRAM_ALLOC_LEN
	// use the whole psram
	size_t len;
	psram = esp_psram_get(&len);
	psram_len = len;
#else
	psram_len = PSRAM_ALLOC_LEN;
	psram = heap_caps_calloc(1, psram_len, MALLOC_CAP_SPIRAM);
#endif

	const static char *files[] = {
		"/sdcard/tiny386.ini",
		"/spiflash/tiny386.ini",
		NULL,
	};
	static struct esp_ini_config config;
	for (int i = 0; files[i]; i++) {
		if (ini_parse(files[i], parse_ini, &config) == 0) {
			config.filename = files[i];
			break;
		}
	}
	if (config.ssid[0]) {
		wifi_main(config.ssid, config.pass);
	}

	if (psram) {
		xTaskCreatePinnedToCore(i386_task, "i386_main", 4096, &config, 3, NULL, 1);
		xTaskCreatePinnedToCore(vga_task, "vga_task", 4096, NULL, 0, NULL, 0);
	}
}
