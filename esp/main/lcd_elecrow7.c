#ifdef USE_LCD_RGB_ELECROW7
/*
 * LCD driver for Elecrow CrowPanel Advance 7" HMI (ESP32-S3)
 *
 * Display: 800x480 RGB565 parallel, ESP32-S3 built-in RGB LCD controller
 * Backlight: I2C via CH422G I/O expander (SDA=15, SCL=16)
 * SD card handled separately via SPI in storage.c
 *
 * Frame buffer architecture: num_fbs=1, single buffer in PSRAM.
 * The VGA renderer writes directly to the panel FB (zero-copy);
 * the RGB DMA controller scans it continuously.
 */

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_rgb.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_touch_gt911.h"

#include "common.h"

/* From i8042.h — PS/2 mouse event injection */
typedef struct PS2MouseState PS2MouseState;
void ps2_mouse_event(PS2MouseState *s, int dx, int dy, int dz, int buttons_state);

static const char *TAG = "lcd";

/* ---- Pixel clock preset 1 (known working per README) ---- */
#define LCD_PCLK_HZ         (15 * 1000 * 1000)
#define LCD_PCLK_ACTIVE_NEG  1
#define LCD_PCLK_IDLE_HIGH   0

/* ---- RGB timing (symmetric 4/8/8) ---- */
#define LCD_HSYNC_PW   4
#define LCD_HSYNC_BP   8
#define LCD_HSYNC_FP   8
#define LCD_VSYNC_PW   4
#define LCD_VSYNC_BP   8
#define LCD_VSYNC_FP   8

/* ---- Control GPIOs ---- */
#define LCD_GPIO_PCLK   39
#define LCD_GPIO_HSYNC  40
#define LCD_GPIO_VSYNC  41
#define LCD_GPIO_DE     42
#define LCD_GPIO_DISP   (-1)  /* not used */

/* ---- 16-bit data bus (D0=LSB .. D15=MSB) ---- */
#define LCD_GPIO_D0   21
#define LCD_GPIO_D1   47
#define LCD_GPIO_D2   48
#define LCD_GPIO_D3   45
#define LCD_GPIO_D4   38
#define LCD_GPIO_D5    9
#define LCD_GPIO_D6   10
#define LCD_GPIO_D7   11
#define LCD_GPIO_D8   12
#define LCD_GPIO_D9   13
#define LCD_GPIO_D10  14
#define LCD_GPIO_D11   7
#define LCD_GPIO_D12  17
#define LCD_GPIO_D13  18
#define LCD_GPIO_D14   3
#define LCD_GPIO_D15  46

/* ---- Bounce buffer: 4 scan lines reduces MSPI contention ---- */
#define LCD_BOUNCE_BUF_LINES 4
#define LCD_BOUNCE_BUF_PX   (LCD_WIDTH * LCD_BOUNCE_BUF_LINES)

/* ---- I2C backlight ---- */
#define BL_I2C_PORT      I2C_NUM_0
#define BL_I2C_TIMEOUT   pdMS_TO_TICKS(100)

static void i2c_write_byte(uint8_t addr, uint8_t cmd)
{
	i2c_master_write_to_device(BL_I2C_PORT, addr, &cmd, 1, BL_I2C_TIMEOUT);
}

static void backlight_init(void)
{
	i2c_config_t cfg = {
		.mode             = I2C_MODE_MASTER,
		.sda_io_num       = LCD_I2C_SDA,
		.scl_io_num       = LCD_I2C_SCL,
		.sda_pullup_en    = GPIO_PULLUP_ENABLE,
		.scl_pullup_en    = GPIO_PULLUP_ENABLE,
		.master.clk_speed = 400000,
	};
	ESP_ERROR_CHECK(i2c_param_config(BL_I2C_PORT, &cfg));
	ESP_ERROR_CHECK(i2c_driver_install(BL_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0));

	/*
	 * Primary path — CH422G I/O expander:
	 *   addr 0x30  cmd 0x18   (STC brightness)
	 *   addr 0x30  cmd 0x10   (STC enable)
	 *   addr 0x24  cmd 0x01   (CH422G: configure output mode)
	 *   addr 0x38  cmd 0x1E   (CH422G: backlight ON)
	 *
	 * Fallback paths tried if CH422G does not ACK.
	 */
	i2c_write_byte(0x30, 0x18);
	i2c_write_byte(0x30, 0x10);

	esp_err_t r;
	uint8_t ch422g_cfg = 0x01;
	r = i2c_master_write_to_device(BL_I2C_PORT, 0x24,
	                               &ch422g_cfg, 1, BL_I2C_TIMEOUT);
	if (r == ESP_OK) {
		/* CH422G present */
		i2c_write_byte(0x38, 0x1E);
		ESP_LOGI(TAG, "Backlight ON via CH422G");
	} else {
		/* Fallback: STC variant at 0x5D */
		i2c_write_byte(0x5D, 0x10);
		/* Fallback: PCA9535 */
		uint8_t pca_init[] = {0x03, 0x00};
		i2c_master_write_to_device(BL_I2C_PORT, 0x57,
		                           pca_init, sizeof(pca_init), BL_I2C_TIMEOUT);
		uint8_t pca_on[] = {0x01, 0xFF};
		i2c_master_write_to_device(BL_I2C_PORT, 0x57,
		                           pca_on, sizeof(pca_on), BL_I2C_TIMEOUT);
		ESP_LOGW(TAG, "Backlight: CH422G not found, tried fallback paths");
	}
}

void pc_vga_step(void *o);

/* ---- GT911 touch controller ---- */

static esp_lcd_touch_handle_t touch_init(void)
{
	esp_lcd_panel_io_handle_t io_handle = NULL;
	const esp_lcd_panel_io_i2c_config_t io_cfg = ESP_LCD_TOUCH_IO_I2C_GT911_CONFIG();

	esp_err_t ret = esp_lcd_new_panel_io_i2c(
		(esp_lcd_i2c_bus_handle_t)BL_I2C_PORT, &io_cfg, &io_handle);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "GT911 panel IO init failed: %s", esp_err_to_name(ret));
		return NULL;
	}

	const esp_lcd_touch_config_t tp_cfg = {
		.x_max = LCD_WIDTH,
		.y_max = LCD_HEIGHT,
		.rst_gpio_num = -1,
		.int_gpio_num = -1,
		.levels = { .reset = 0, .interrupt = 0 },
		.flags = { .swap_xy = 0, .mirror_x = 0, .mirror_y = 0 },
	};

	esp_lcd_touch_handle_t tp = NULL;
	ret = esp_lcd_touch_new_i2c_gt911(io_handle, &tp_cfg, &tp);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "GT911 init failed: %s", esp_err_to_name(ret));
		return NULL;
	}

	ESP_LOGI(TAG, "GT911 touch controller initialized");
	return tp;
}

/* ---- Touch polling and gesture detection ---- */

#define TAP_MAX_MS      200   /* max duration for a tap gesture */
#define TAP_MAX_PX      10    /* max movement for a tap gesture */

static void touch_poll(esp_lcd_touch_handle_t tp)
{
	static bool was_touching = false;
	static uint16_t prev_x, prev_y;
	static TickType_t touch_start_tick;
	static uint16_t start_x, start_y;
	static bool was_two_finger = false;

	uint16_t x[2], y[2];
	uint8_t cnt = 0;

	esp_lcd_touch_read_data(tp);
	esp_lcd_touch_get_coordinates(tp, x, y, NULL, &cnt, 2);

	if (cnt >= 2)
		was_two_finger = true;

	if (cnt >= 1) {
		if (was_touching) {
			/* Finger still down — send relative movement */
			int dx = (int)x[0] - (int)prev_x;
			int dy = (int)y[0] - (int)prev_y;
			if (dx != 0 || dy != 0)
				ps2_mouse_event(globals.mouse, dx, dy, 0, 0);
		} else {
			/* Finger just went down */
			touch_start_tick = xTaskGetTickCount();
			start_x = x[0];
			start_y = y[0];
			was_two_finger = (cnt >= 2);
		}
		prev_x = x[0];
		prev_y = y[0];
		was_touching = true;
	} else if (was_touching) {
		/* Finger just lifted — check for tap */
		TickType_t dur = xTaskGetTickCount() - touch_start_tick;
		int move_x = abs((int)prev_x - (int)start_x);
		int move_y = abs((int)prev_y - (int)start_y);

		if (pdTICKS_TO_MS(dur) < TAP_MAX_MS &&
		    move_x < TAP_MAX_PX && move_y < TAP_MAX_PX) {
			if (was_two_finger) {
				/* Two-finger tap → right click */
				ps2_mouse_event(globals.mouse, 0, 0, 0, 2);
				ps2_mouse_event(globals.mouse, 0, 0, 0, 0);
			} else {
				/* Single tap → left click */
				ps2_mouse_event(globals.mouse, 0, 0, 0, 1);
				ps2_mouse_event(globals.mouse, 0, 0, 0, 0);
			}
		}
		was_touching = false;
		was_two_finger = false;
	}
}

/*
 * lcd_draw() — no-op for elecrow7.
 *
 * The VGA renderer writes directly to globals.panel_fb which is the
 * panel's DMA frame buffer.  The RGB DMA controller scans it
 * continuously, so no explicit push is required.
 */
void lcd_draw(int x_start, int y_start, int x_end, int y_end, void *src)
{
	(void)x_start; (void)y_start; (void)x_end; (void)y_end; (void)src;
}

void vga_task(void *arg)
{
	int core_id = esp_cpu_get_core_id();
	fprintf(stderr, "vga runs on core %d\n", core_id);

	/* ------ Backlight ------ */
	ESP_LOGI(TAG, "Init backlight");
	backlight_init();

	/* ------ Touch controller ------ */
	ESP_LOGI(TAG, "Init touch controller");
	esp_lcd_touch_handle_t tp = touch_init();

	/* ------ RGB panel ------ */
	ESP_LOGI(TAG, "Init RGB LCD panel");

	esp_lcd_rgb_panel_config_t panel_cfg = {
		.clk_src   = LCD_CLK_SRC_DEFAULT,
		.timings   = {
			.pclk_hz          = LCD_PCLK_HZ,
			.h_res            = LCD_WIDTH,
			.v_res            = LCD_HEIGHT,
			.hsync_pulse_width = LCD_HSYNC_PW,
			.hsync_back_porch  = LCD_HSYNC_BP,
			.hsync_front_porch = LCD_HSYNC_FP,
			.vsync_pulse_width = LCD_VSYNC_PW,
			.vsync_back_porch  = LCD_VSYNC_BP,
			.vsync_front_porch = LCD_VSYNC_FP,
			.flags = {
				.pclk_active_neg = LCD_PCLK_ACTIVE_NEG,
				.pclk_idle_high  = LCD_PCLK_IDLE_HIGH,
			},
		},
		.data_width            = 16,
		.bits_per_pixel        = 16,
		.num_fbs               = 1,
		.bounce_buffer_size_px = LCD_BOUNCE_BUF_PX,
		.psram_trans_align     = 64,
		.hsync_gpio_num        = LCD_GPIO_HSYNC,
		.vsync_gpio_num        = LCD_GPIO_VSYNC,
		.de_gpio_num           = LCD_GPIO_DE,
		.pclk_gpio_num         = LCD_GPIO_PCLK,
		.disp_gpio_num         = LCD_GPIO_DISP,
		.data_gpio_nums = {
			LCD_GPIO_D0,  LCD_GPIO_D1,  LCD_GPIO_D2,  LCD_GPIO_D3,
			LCD_GPIO_D4,  LCD_GPIO_D5,  LCD_GPIO_D6,  LCD_GPIO_D7,
			LCD_GPIO_D8,  LCD_GPIO_D9,  LCD_GPIO_D10, LCD_GPIO_D11,
			LCD_GPIO_D12, LCD_GPIO_D13, LCD_GPIO_D14, LCD_GPIO_D15,
		},
		.flags = {
			.fb_in_psram = 1,
		},
	};

	esp_lcd_panel_handle_t panel = NULL;
	ESP_ERROR_CHECK(esp_lcd_new_rgb_panel(&panel_cfg, &panel));
	ESP_ERROR_CHECK(esp_lcd_panel_init(panel));

	/* ------ Get DMA frame buffer pointer ------ */
	void *fb_ptr = NULL;
	ESP_ERROR_CHECK(esp_lcd_rgb_panel_get_frame_buffer(panel, 1, &fb_ptr));
	ESP_LOGI(TAG, "Panel FB @ %p (%d bytes)", fb_ptr, LCD_WIDTH * LCD_HEIGHT * 2);

	globals.panel    = panel;
	globals.panel_fb = fb_ptr;

	/* Signal i386_task that panel (and panel_fb) is ready */
	xEventGroupSetBits(global_event_group, BIT1);

	/* Wait for PC emulator to be initialised */
	xEventGroupWaitBits(global_event_group,
	                    BIT0,
	                    pdFALSE,
	                    pdFALSE,
	                    portMAX_DELAY);

	/* ------ VGA + touch loop (~15 fps cap) ------ */
	while (1) {
		pc_vga_step(globals.pc);
		if (tp)
			touch_poll(tp);
		vTaskDelay(pdMS_TO_TICKS(67));
	}
}

#endif /* USE_LCD_RGB_ELECROW7 */
