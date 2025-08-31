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
#include "driver/sdmmc_host.h"
#include "driver/i2s_std.h"
#include "driver/gpio.h"

#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"

static const char *TAG = "esp_main";

int main(int argc, char *argv[]);
void *esp_psram_get(size_t *size);

static void i386_task(void *arg)
{
	int core_id = esp_cpu_get_core_id();
	fprintf(stderr, "main runs on core %d\n", core_id);
	char *argv[4];
	argv[0] = "tiny386";
//	argv[1] = "/sdcard/dos622.img";
//	argv[1] = "/sdcard/winnt4c.img";
//	argv[1] = "/sdcard/win95c.img";
	argv[1] = "/sdcard/win98lite.img";
	argv[2] = "/sdcard/disk128m.img";
	argv[3] = NULL;
	main(4, argv);
	vTaskDelete(NULL);
}

#include "esp_log.h"
#include "esp_lcd_panel_io_interface.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_axs15231b.h"
#include "driver/ledc.h"

#define TEST_LCD_BIT_PER_PIXEL          (16)
#define TEST_DELAY_TIME_MS              (3000)
#define TEST_READ_TIME_MS               (3000)
#define TEST_READ_PERIOD_MS             (30)

/* SPI & QSPI */
#define TEST_LCD_SPI_H_RES              (320)
#define TEST_LCD_SPI_V_RES              (480)
#define TEST_LCD_SPI_HOST               (SPI2_HOST)
#define TEST_PIN_NUM_SPI_CS             (GPIO_NUM_45)
#define TEST_PIN_NUM_SPI_PCLK           (GPIO_NUM_47)
#define TEST_PIN_NUM_SPI_DATA0          (GPIO_NUM_21)
#define TEST_PIN_NUM_SPI_DATA1          (GPIO_NUM_48)
#define TEST_PIN_NUM_SPI_DATA2          (GPIO_NUM_40)
#define TEST_PIN_NUM_SPI_DATA3          (GPIO_NUM_39)
#define TEST_PIN_NUM_SPI_RST            (GPIO_NUM_NC)
#define TEST_PIN_NUM_SPI_DC             (GPIO_NUM_8)
#define TEST_PIN_NUM_SPI_BL             (GPIO_NUM_1)

static SemaphoreHandle_t refresh_finish = NULL;

static const axs15231b_lcd_init_cmd_t lcd_init_cmds[] = {
	{0xBB, (uint8_t []){0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5A, 0xA5}, 8, 0},
	{0xA0, (uint8_t []){0xC0, 0x10, 0x00, 0x02, 0x00, 0x00, 0x04, 0x3F, 0x20, 0x05, 0x3F, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00}, 17, 0},
	{0xA2, (uint8_t []){0x30, 0x3C, 0x24, 0x14, 0xD0, 0x20, 0xFF, 0xE0, 0x40, 0x19, 0x80, 0x80, 0x80, 0x20, 0xf9, 0x10, 0x02, 0xff, 0xff, 0xF0, 0x90, 0x01, 0x32, 0xA0, 0x91, 0xE0, 0x20, 0x7F, 0xFF, 0x00, 0x5A}, 31, 0},
	{0xD0, (uint8_t []){0xE0, 0x40, 0x51, 0x24, 0x08, 0x05, 0x10, 0x01, 0x20, 0x15, 0x42, 0xC2, 0x22, 0x22, 0xAA, 0x03, 0x10, 0x12, 0x60, 0x14, 0x1E, 0x51, 0x15, 0x00, 0x8A, 0x20, 0x00, 0x03, 0x3A, 0x12}, 30, 0},
	{0xA3, (uint8_t []){0xA0, 0x06, 0xAa, 0x00, 0x08, 0x02, 0x0A, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x55, 0x55}, 22, 0},
	{0xC1, (uint8_t []){0x31, 0x04, 0x02, 0x02, 0x71, 0x05, 0x24, 0x55, 0x02, 0x00, 0x41, 0x00, 0x53, 0xFF, 0xFF, 0xFF, 0x4F, 0x52, 0x00, 0x4F, 0x52, 0x00, 0x45, 0x3B, 0x0B, 0x02, 0x0d, 0x00, 0xFF, 0x40}, 30, 0},
	{0xC3, (uint8_t []){0x00, 0x00, 0x00, 0x50, 0x03, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01}, 11, 0},
	{0xC4, (uint8_t []){0x00, 0x24, 0x33, 0x80, 0x00, 0xea, 0x64, 0x32, 0xC8, 0x64, 0xC8, 0x32, 0x90, 0x90, 0x11, 0x06, 0xDC, 0xFA, 0x00, 0x00, 0x80, 0xFE, 0x10, 0x10, 0x00, 0x0A, 0x0A, 0x44, 0x50}, 29, 0},
	{0xC5, (uint8_t []){0x18, 0x00, 0x00, 0x03, 0xFE, 0x3A, 0x4A, 0x20, 0x30, 0x10, 0x88, 0xDE, 0x0D, 0x08, 0x0F, 0x0F, 0x01, 0x3A, 0x4A, 0x20, 0x10, 0x10, 0x00}, 23, 0},
	{0xC6, (uint8_t []){0x05, 0x0A, 0x05, 0x0A, 0x00, 0xE0, 0x2E, 0x0B, 0x12, 0x22, 0x12, 0x22, 0x01, 0x03, 0x00, 0x3F, 0x6A, 0x18, 0xC8, 0x22}, 20, 0},
	{0xC7, (uint8_t []){0x50, 0x32, 0x28, 0x00, 0xa2, 0x80, 0x8f, 0x00, 0x80, 0xff, 0x07, 0x11, 0x9c, 0x67, 0xff, 0x24, 0x0c, 0x0d, 0x0e, 0x0f}, 20, 0},
	{0xC9, (uint8_t []){0x33, 0x44, 0x44, 0x01}, 4, 0},
	{0xCF, (uint8_t []){0x2C, 0x1E, 0x88, 0x58, 0x13, 0x18, 0x56, 0x18, 0x1E, 0x68, 0x88, 0x00, 0x65, 0x09, 0x22, 0xC4, 0x0C, 0x77, 0x22, 0x44, 0xAA, 0x55, 0x08, 0x08, 0x12, 0xA0, 0x08}, 27, 0},
	{0xD5, (uint8_t []){0x40, 0x8E, 0x8D, 0x01, 0x35, 0x04, 0x92, 0x74, 0x04, 0x92, 0x74, 0x04, 0x08, 0x6A, 0x04, 0x46, 0x03, 0x03, 0x03, 0x03, 0x82, 0x01, 0x03, 0x00, 0xE0, 0x51, 0xA1, 0x00, 0x00, 0x00}, 30, 0},
	{0xD6, (uint8_t []){0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x93, 0x00, 0x01, 0x83, 0x07, 0x07, 0x00, 0x07, 0x07, 0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x84, 0x00, 0x20, 0x01, 0x00}, 30, 0},
	{0xD7, (uint8_t []){0x03, 0x01, 0x0b, 0x09, 0x0f, 0x0d, 0x1E, 0x1F, 0x18, 0x1d, 0x1f, 0x19, 0x40, 0x8E, 0x04, 0x00, 0x20, 0xA0, 0x1F}, 19, 0},
	{0xD8, (uint8_t []){0x02, 0x00, 0x0a, 0x08, 0x0e, 0x0c, 0x1E, 0x1F, 0x18, 0x1d, 0x1f, 0x19}, 12, 0},
	{0xD9, (uint8_t []){0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F}, 12, 0},
	{0xDD, (uint8_t []){0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F}, 12, 0},
	{0xDF, (uint8_t []){0x44, 0x73, 0x4B, 0x69, 0x00, 0x0A, 0x02, 0x90}, 8,  0},
	{0xE0, (uint8_t []){0x3B, 0x28, 0x10, 0x16, 0x0c, 0x06, 0x11, 0x28, 0x5c, 0x21, 0x0D, 0x35, 0x13, 0x2C, 0x33, 0x28, 0x0D}, 17, 0},
	{0xE1, (uint8_t []){0x37, 0x28, 0x10, 0x16, 0x0b, 0x06, 0x11, 0x28, 0x5C, 0x21, 0x0D, 0x35, 0x14, 0x2C, 0x33, 0x28, 0x0F}, 17, 0},
	{0xE2, (uint8_t []){0x3B, 0x07, 0x12, 0x18, 0x0E, 0x0D, 0x17, 0x35, 0x44, 0x32, 0x0C, 0x14, 0x14, 0x36, 0x3A, 0x2F, 0x0D}, 17, 0},
	{0xE3, (uint8_t []){0x37, 0x07, 0x12, 0x18, 0x0E, 0x0D, 0x17, 0x35, 0x44, 0x32, 0x0C, 0x14, 0x14, 0x36, 0x32, 0x2F, 0x0F}, 17, 0},
	{0xE4, (uint8_t []){0x3B, 0x07, 0x12, 0x18, 0x0E, 0x0D, 0x17, 0x39, 0x44, 0x2E, 0x0C, 0x14, 0x14, 0x36, 0x3A, 0x2F, 0x0D}, 17, 0},
	{0xE5, (uint8_t []){0x37, 0x07, 0x12, 0x18, 0x0E, 0x0D, 0x17, 0x39, 0x44, 0x2E, 0x0C, 0x14, 0x14, 0x36, 0x3A, 0x2F, 0x0F}, 17, 0},
	{0xA4, (uint8_t []){0x85, 0x85, 0x95, 0x82, 0xAF, 0xAA, 0xAA, 0x80, 0x10, 0x30, 0x40, 0x40, 0x20, 0xFF, 0x60, 0x30}, 16, 0},
	{0xA4, (uint8_t []){0x85, 0x85, 0x95, 0x85}, 4, 0},
	{0xBB, (uint8_t []){0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 8, 0},
	{0x13, (uint8_t []){0x00}, 0, 0},
	{0x11, (uint8_t []){0x00}, 0, 120},
	{0x2C, (uint8_t []){0x00, 0x00, 0x00, 0x00}, 4, 0},
};

#define LCD_LEDC_CH            1
static esp_err_t bsp_display_brightness_init(void)
{
	// Setup LEDC peripheral for PWM backlight control
	const ledc_channel_config_t LCD_backlight_channel = {
		.gpio_num = TEST_PIN_NUM_SPI_BL,
		.speed_mode = LEDC_LOW_SPEED_MODE,
		.channel = LCD_LEDC_CH,
		.intr_type = LEDC_INTR_DISABLE,
		.timer_sel = 1,
		.duty = 0,
		.hpoint = 0
	};
	const ledc_timer_config_t LCD_backlight_timer = {
		.speed_mode = LEDC_LOW_SPEED_MODE,
		.duty_resolution = LEDC_TIMER_10_BIT,
		.timer_num = 1,
		.freq_hz = 5000,
		.clk_cfg = LEDC_AUTO_CLK
	};

	ESP_ERROR_CHECK(ledc_timer_config(&LCD_backlight_timer));
	ESP_ERROR_CHECK(ledc_channel_config(&LCD_backlight_channel));

	return ESP_OK;
}

esp_err_t bsp_display_brightness_set(int brightness_percent)
{
	if (brightness_percent > 100) {
		brightness_percent = 100;
	}
	if (brightness_percent < 0) {
		brightness_percent = 0;
	}

	ESP_LOGI(TAG, "Setting LCD backlight: %d%%", brightness_percent);
	uint32_t duty_cycle = (1023 * brightness_percent) / 100; // LEDC resolution set to 10bits, thus: 100% = 1023
	ESP_ERROR_CHECK(ledc_set_duty(LEDC_LOW_SPEED_MODE, LCD_LEDC_CH, duty_cycle));
	ESP_ERROR_CHECK(ledc_update_duty(LEDC_LOW_SPEED_MODE, LCD_LEDC_CH));

	return ESP_OK;
}

void *thepc;
void *thepanel;
void pc_vga_step(void *o);
static void vga_task(void *arg)
{
	int core_id = esp_cpu_get_core_id();
	fprintf(stderr, "vga runs on core %d\n", core_id);

	ESP_LOGI(TAG, "Initialize BL");
	gpio_config_t init_gpio_config = {
		.mode = GPIO_MODE_OUTPUT,
		.pin_bit_mask = (1ULL << TEST_PIN_NUM_SPI_BL),
	};
	ESP_ERROR_CHECK(gpio_config(&init_gpio_config));
	gpio_set_level(TEST_PIN_NUM_SPI_BL, 1);

	ESP_LOGI(TAG, "Initialize SPI bus");
	const spi_bus_config_t buscfg = AXS15231B_PANEL_BUS_QSPI_CONFIG(TEST_PIN_NUM_SPI_PCLK,
									TEST_PIN_NUM_SPI_DATA0,
									TEST_PIN_NUM_SPI_DATA1,
									TEST_PIN_NUM_SPI_DATA2,
									TEST_PIN_NUM_SPI_DATA3,
									TEST_LCD_SPI_H_RES * TEST_LCD_SPI_V_RES * TEST_LCD_BIT_PER_PIXEL / 8);
	ESP_ERROR_CHECK(spi_bus_initialize(TEST_LCD_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

	ESP_LOGI(TAG, "Install panel IO");
	esp_lcd_panel_io_handle_t io_handle = NULL;

	esp_lcd_panel_io_spi_config_t io_config = AXS15231B_PANEL_IO_QSPI_CONFIG(TEST_PIN_NUM_SPI_CS, NULL, NULL);

	// Attach the LCD to the SPI bus
	ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)TEST_LCD_SPI_HOST, &io_config, &io_handle));

	ESP_LOGI(TAG, "Install AXS15231B panel driver");
	esp_lcd_panel_handle_t panel_handle = NULL;
	const axs15231b_vendor_config_t vendor_config = {
		.init_cmds = lcd_init_cmds,
		.init_cmds_size = sizeof(lcd_init_cmds) / sizeof(lcd_init_cmds[0]),
		.flags = {
			.use_qspi_interface = 1,
		},
	};
	const esp_lcd_panel_dev_config_t panel_config = {
		.reset_gpio_num = TEST_PIN_NUM_SPI_RST,
		.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
		.bits_per_pixel = TEST_LCD_BIT_PER_PIXEL,
		.vendor_config = (void *) &vendor_config,
	};
	ESP_ERROR_CHECK(esp_lcd_new_panel_axs15231b(io_handle, &panel_config, &panel_handle));
	esp_lcd_panel_reset(panel_handle);
	esp_lcd_panel_init(panel_handle);
	esp_lcd_panel_mirror(panel_handle, true, false);
	esp_lcd_panel_disp_on_off(panel_handle, false); // false means "ON" for axs15231b...

	bsp_display_brightness_init();
	bsp_display_brightness_set(30);

	thepanel = panel_handle;
	while (1) {
		if (thepc)
			pc_vga_step(thepc);
		vTaskDelay(10 / portTICK_PERIOD_MS);
	}

	ESP_ERROR_CHECK(esp_lcd_panel_del(panel_handle));
	ESP_ERROR_CHECK(esp_lcd_panel_io_del(io_handle));
	ESP_ERROR_CHECK(spi_bus_free(TEST_LCD_SPI_HOST));
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

static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

static i2s_chan_handle_t                tx_chan;        // I2S tx channel handler
void mixer_callback (void *opaque, uint8_t *stream, int free);

static void i2s_task(void *arg)
{
	static int16_t buf[128];
	int core_id = esp_cpu_get_core_id();
	fprintf(stderr, "i2s runs on core %d\n", core_id);

	while (!thepc)
		usleep(200000);

	i2s_channel_enable(tx_chan);
	for (;;) {
		size_t bwritten;
		memset(buf, 0, 128 * 2);
		mixer_callback(thepc, buf, 128 * 2);
		for (int i = 0; i < 128; i++) {
			buf[i] = buf[i] / 16;
		}
		i2s_channel_write(tx_chan, buf, 128 * 2, &bwritten, portMAX_DELAY);
	}
	i2s_channel_disable(tx_chan);
}

void i2s_main()
{
	/* Setp 1: Determine the I2S channel configuration and allocate two channels one by one
	 * The default configuration can be generated by the helper macro,
	 * it only requires the I2S controller id and I2S role
	 * The tx and rx channels here are registered on different I2S controller,
	 * Except ESP32 and ESP32-S2, others allow to register two separate tx & rx channels on a same controller */
	i2s_chan_config_t tx_chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
	ESP_ERROR_CHECK(i2s_new_channel(&tx_chan_cfg, &tx_chan, NULL));

	/* Step 2: Setting the configurations of standard mode and initialize each channels one by one
	 * The slot configuration and clock configuration can be generated by the macros
	 * These two helper macros is defined in 'i2s_std.h' which can only be used in STD mode.
	 * They can help to specify the slot and clock configurations for initialization or re-configuring */
	i2s_std_config_t tx_std_cfg = {
		.clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(44100),
		.slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_STEREO),
		.gpio_cfg = {
			.mclk = I2S_GPIO_UNUSED,    // some codecs may require mclk signal, this example doesn't need it
			.bclk = 42,
			.ws   = 2,
			.dout = 41,
			.din  = -1,
			.invert_flags = {
				.mclk_inv = false,
				.bclk_inv = false,
				.ws_inv   = false,
			},
		},
	};
	ESP_ERROR_CHECK(i2s_channel_init_std_mode(tx_chan, &tx_std_cfg));
	xTaskCreatePinnedToCore(i2s_task, "i2s_task", 4608, NULL, 0, NULL, 0);
}

void wifi_main();
void app_main(void)
{
	wifi_main();
	i2s_main();

#if 0
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

	// Options for mounting the filesystem.
	esp_vfs_fat_sdmmc_mount_config_t sdmount_config = {
		.format_if_mount_failed = false,
		.max_files = 5,
		.allocation_unit_size = 16 * 1024
	};
	sdmmc_card_t *card;
	ESP_LOGI(TAG, "Initializing SD card");

	// Use settings defined above to initialize SD card and mount FAT filesystem.
	// Note: esp_vfs_fat_sdmmc/sdspi_mount is all-in-one convenience functions.
	// Please check its source code and implement error recovery when developing
	// production applications.
	ESP_LOGI(TAG, "Using SDMMC peripheral");

	// By default, SD card frequency is initialized to SDMMC_FREQ_DEFAULT (20MHz)
	// For setting a specific frequency, use host.max_freq_khz (range 400kHz - 40MHz for SDMMC)
	// Example: for fixed frequency of 10MHz, use host.max_freq_khz = 10000;
	sdmmc_host_t host = SDMMC_HOST_DEFAULT();
	host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;

	// This initializes the slot without card detect (CD) and write protect (WP) signals.
	// Modify slot_config.gpio_cd and slot_config.gpio_wp if your board has these signals.
	sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();

	// Set bus width to use:
	slot_config.width = 1;

	// On chips where the GPIOs used for SD card can be configured, set them in
	// the slot_config structure:
	slot_config.clk = 12;
	slot_config.cmd = 11;
	slot_config.d0 = 13;

	// Enable internal pullups on enabled pins. The internal pullups
	// are insufficient however, please make sure 10k external pullups are
	// connected on the bus. This is for debug / example purpose only.
	slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

	ESP_LOGI(TAG, "Mounting filesystem");
	esp_err_t ret;
	ret = esp_vfs_fat_sdmmc_mount("/sdcard", &host, &slot_config, &sdmount_config, &card);

	if (ret != ESP_OK) {
		if (ret == ESP_FAIL) {
			ESP_LOGE(TAG, "Failed to mount filesystem. "
				 "If you want the card to be formatted, set the EXAMPLE_FORMAT_IF_MOUNT_FAILED menuconfig option.");
		} else {
			ESP_LOGE(TAG, "Failed to initialize the card (%s). "
				 "Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
		}
	} else {
		ESP_LOGI(TAG, "Filesystem mounted");
	}

#if 0
	const esp_vfs_fat_mount_config_t mount_config = {
		.max_files = 4,
		.format_if_mount_failed = true,
		.allocation_unit_size = CONFIG_WL_SECTOR_SIZE
	};

	if(esp_vfs_fat_spiflash_mount_rw_wl("/spiflash", "storage",
					    &mount_config, &s_wl_handle) != ESP_OK) {
		assert(false);
	}
#endif

	size_t len;
	esp_psram_init();
	psram = esp_psram_get(&len);
	psram_len = len;
	if (psram) {
		xTaskCreatePinnedToCore(i386_task, "i386_main", 4608, NULL, 3, NULL, 1);
		xTaskCreatePinnedToCore(vga_task, "vga_task", 4608, NULL, 0, NULL, 0);
	}
}
