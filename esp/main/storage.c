#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/sdmmc_host.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"
#include "sdmmc_cmd.h"
#include "common.h"

static const char *TAG = "storage";
void *rawsd;
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

void storage_init(void)
{
	bool sd_mount_ok = false;
#ifdef SD_CLK
#ifndef USE_RAWSD
	// Options for mounting the filesystem.
	esp_vfs_fat_sdmmc_mount_config_t sdmount_config = {
		.format_if_mount_failed = false,
		.max_files = 3,
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
		sd_mount_ok = true;
	}
#else
	sdmmc_card_t *card = malloc(sizeof(sdmmc_card_t));
	memset(card, 0, sizeof(sdmmc_card_t));
	ESP_LOGI(TAG, "Initializing SD card");
	ESP_LOGI(TAG, "Using SDMMC peripheral");
	sdmmc_host_t host = SDMMC_HOST_DEFAULT();
	host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;

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

	esp_err_t ret;
	ret = host.init();
	assert(ret == 0);
	ret = sdmmc_host_init_slot(host.slot, &slot_config);
	assert(ret == 0);
	ret = sdmmc_card_init(&host, card);
	assert(ret == 0);
	sdmmc_card_print_info(stderr, card);
#endif
	rawsd = card;
#endif /* SD_CLK */
	// mount spiflash, only if sdcard is not mounted
	// to save memroy
	if (!sd_mount_ok) {
		const esp_vfs_fat_mount_config_t mount_config = {
			.max_files = 4,
			.format_if_mount_failed = false,
			.allocation_unit_size = CONFIG_WL_SECTOR_SIZE
		};
		esp_vfs_fat_spiflash_mount_rw_wl("/spiflash", "storage",
						 &mount_config, &s_wl_handle);
	}
}
