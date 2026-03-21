#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/sdmmc_host.h"
#include "driver/i2c.h"
#include "driver/spi_common.h"
#include "driver/sdspi_host.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"
#include "sdmmc_cmd.h"
#include "common.h"
#ifdef SD_PWR_CTRL_LDO_IO_ID
#include "sd_pwr_ctrl_by_on_chip_ldo.h"
#endif

static const char *TAG = "storage";
void *rawsd;
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

#ifdef USE_HOSTED_WIFI
static esp_err_t sdmmc_host_init_dummy(void)
{
	return ESP_OK;
}

static esp_err_t sdmmc_host_deinit_dummy(void)
{
	return ESP_OK;
}
#endif

void storage_init(void)
{
	bool sd_mount_ok = false;
#ifdef SD_CLK
#ifndef USE_RAWSD
	// Options for mounting the filesystem.
	esp_vfs_fat_sdmmc_mount_config_t sdmount_config = {
		.format_if_mount_failed = false,
		.max_files = 5,
		.allocation_unit_size = 16 * 1024
	};
	sdmmc_card_t *card;
	esp_err_t ret;
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
#ifdef USE_HOSTED_WIFI
	host.slot = SDMMC_HOST_SLOT_0;
	host.init = &sdmmc_host_init_dummy;
	host.deinit = &sdmmc_host_deinit_dummy;
#endif

	// For SoCs where the SD power can be supplied both via an internal or external (e.g. on-board LDO) power supply.
	// When using specific IO pins (which can be used for ultra high-speed SDMMC) to connect to the SD card
	// and the internal LDO power supply, we need to initialize the power supply first.
#ifdef SD_PWR_CTRL_LDO_IO_ID
	sd_pwr_ctrl_ldo_config_t ldo_config = {
		.ldo_chan_id = SD_PWR_CTRL_LDO_IO_ID,
	};
	sd_pwr_ctrl_handle_t pwr_ctrl_handle = NULL;

	ret = sd_pwr_ctrl_new_on_chip_ldo(&ldo_config, &pwr_ctrl_handle);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to create a new on-chip LDO power control driver");
		return;
	}
	host.pwr_ctrl_handle = pwr_ctrl_handle;
#endif

	// This initializes the slot without card detect (CD) and write protect (WP) signals.
	// Modify slot_config.gpio_cd and slot_config.gpio_wp if your board has these signals.
	sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();

#ifdef SD_D3
	slot_config.width = 4;
	slot_config.clk = SD_CLK;
	slot_config.cmd = SD_CMD;
	slot_config.d0 = SD_D0;
	slot_config.d1 = SD_D1;
	slot_config.d2 = SD_D2;
	slot_config.d3 = SD_D3;
#else
	slot_config.width = 1;
	slot_config.clk = SD_CLK;
	slot_config.cmd = SD_CMD;
	slot_config.d0 = SD_D0;
#endif
	slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

	ESP_LOGI(TAG, "Mounting filesystem");
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
		sd_mount_ok = true;
	}
#else
	esp_err_t ret;
	sdmmc_card_t *card = malloc(sizeof(sdmmc_card_t));
	memset(card, 0, sizeof(sdmmc_card_t));
	ESP_LOGI(TAG, "Initializing SD card");
	ESP_LOGI(TAG, "Using SDMMC peripheral");
	sdmmc_host_t host = SDMMC_HOST_DEFAULT();
	host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;
#ifdef USE_HOSTED_WIFI
	host.slot = SDMMC_HOST_SLOT_0;
	host.init = &sdmmc_host_init_dummy;
	host.deinit = &sdmmc_host_deinit_dummy;
#endif

#ifdef SD_PWR_CTRL_LDO_IO_ID
	sd_pwr_ctrl_ldo_config_t ldo_config = {
		.ldo_chan_id = SD_PWR_CTRL_LDO_IO_ID,
	};
	sd_pwr_ctrl_handle_t pwr_ctrl_handle = NULL;

	ret = sd_pwr_ctrl_new_on_chip_ldo(&ldo_config, &pwr_ctrl_handle);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to create a new on-chip LDO power control driver");
		return;
	}
	host.pwr_ctrl_handle = pwr_ctrl_handle;
#endif
	sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
#ifdef SD_D3
	slot_config.width = 4;
	slot_config.clk = SD_CLK;
	slot_config.cmd = SD_CMD;
	slot_config.d0 = SD_D0;
	slot_config.d1 = SD_D1;
	slot_config.d2 = SD_D2;
	slot_config.d3 = SD_D3;
#else
	slot_config.width = 1;
	slot_config.clk = SD_CLK;
	slot_config.cmd = SD_CMD;
	slot_config.d0 = SD_D0;
#endif
	slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

	ret = host.init();
	assert(ret == 0);
	ret = sdmmc_host_init_slot(host.slot, &slot_config);
	assert(ret == 0);
	ret = sdmmc_card_init(&host, card);
	assert(ret == 0);
	sdmmc_card_print_info(stderr, card);
#endif
	rawsd = card;
#elif defined(SD_SPI_MOSI)
	/*
	 * elecrow7s3: SPI-mode SD card via SPI2_HOST.
	 *
	 * Before touching the SPI bus, we must enable the TF card power/mux
	 * path through the CH422G I/O expander over I2C.  After sending the
	 * enable command we delete the I2C driver so that lcd_elecrow7s3.c can
	 * re-initialise it cleanly for backlight control.
	 */

	/* ---- I2C pre-init: enable TF card power ---- */
	ESP_LOGI(TAG, "Enabling TF card power via I2C");
	{
		i2c_config_t i2c_cfg = {
			.mode             = I2C_MODE_MASTER,
			.sda_io_num       = LCD_I2C_SDA,
			.scl_io_num       = LCD_I2C_SCL,
			.sda_pullup_en    = GPIO_PULLUP_ENABLE,
			.scl_pullup_en    = GPIO_PULLUP_ENABLE,
			.master.clk_speed = 400000,
		};
		esp_err_t r = i2c_param_config(I2C_NUM_0, &i2c_cfg);
		if (r == ESP_OK)
			r = i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0);
		if (r == ESP_OK) {
			uint8_t cmd = 0x10;
			i2c_master_write_to_device(I2C_NUM_0, 0x30, &cmd, 1,
			                           pdMS_TO_TICKS(100));
			ESP_LOGI(TAG, "TF card power enabled");
		} else {
			ESP_LOGW(TAG, "I2C init failed (%s), skipping TF power-on",
			         esp_err_to_name(r));
		}
		/* 500 ms for power path to settle before first CMD0/CMD8 */
		vTaskDelay(pdMS_TO_TICKS(500));
		/* Release I2C so vga_task can reinit it for backlight */
		i2c_driver_delete(I2C_NUM_0);
	}

	/* ---- SPI bus init ---- */
	ESP_LOGI(TAG, "Initializing SPI2 bus for SD card");
	{
		spi_bus_config_t bus_cfg = {
			.mosi_io_num     = SD_SPI_MOSI,
			.miso_io_num     = SD_SPI_MISO,
			.sclk_io_num     = SD_SPI_SCK,
			.quadwp_io_num   = -1,
			.quadhd_io_num   = -1,
			.max_transfer_sz = 4096,
		};
		ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO));
	}

	/* ---- Mount SD card via FAT/sdspi ---- */
	{
		esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
			.format_if_mount_failed = false,
			.max_files              = 3,
			.allocation_unit_size   = 16 * 1024,
		};

		sdmmc_host_t spi_host = SDSPI_HOST_DEFAULT();
		sdspi_device_config_t slot_cfg = SDSPI_DEVICE_CONFIG_DEFAULT();
		slot_cfg.gpio_cs = SD_SPI_CS;
		slot_cfg.host_id = SPI2_HOST;

		/*
		 * Try mounting at normal speed first, then at 400 kHz as last
		 * resort.  The README notes 40 MHz often fails on first cold boot.
		 */
		static const int freqs_khz[] = {
			SD_SPI_FREQ_KHZ, SD_SPI_FREQ_KHZ, 400
		};
		sdmmc_card_t *card = NULL;
		for (int i = 0;
		     i < (int)(sizeof(freqs_khz) / sizeof(freqs_khz[0]));
		     i++) {
			spi_host.max_freq_khz = freqs_khz[i];
			ESP_LOGI(TAG, "SD mount attempt %d: CS=%d freq=%d kHz",
			         i + 1, (int)slot_cfg.gpio_cs, freqs_khz[i]);
			esp_err_t ret = esp_vfs_fat_sdspi_mount(
				"/sdcard", &spi_host, &slot_cfg, &mount_cfg, &card);
			if (ret == ESP_OK) {
				ESP_LOGI(TAG, "SD card mounted");
				sd_mount_ok = true;
				rawsd = card;
				break;
			}
			ESP_LOGW(TAG, "  failed: %s", esp_err_to_name(ret));
		}
		if (!sd_mount_ok) {
			ESP_LOGE(TAG, "All SD mount attempts failed");
		}
	}
#endif /* SD_CLK / SD_SPI_MOSI */

	// mount spiflash, only if sdcard is not mounted
	// to save memory
	if (!sd_mount_ok) {
		const esp_vfs_fat_mount_config_t spiflash_cfg = {
			.max_files = 4,
			.format_if_mount_failed = false,
			.allocation_unit_size = CONFIG_WL_SECTOR_SIZE
		};
		esp_vfs_fat_spiflash_mount_rw_wl("/spiflash", "storage",
						 &spiflash_cfg, &s_wl_handle);
	}
}
