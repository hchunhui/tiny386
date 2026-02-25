/*
 * sdmmc_crc_wrap.c — CMD59 (CRC on/off) workaround for SPI SD cards
 *
 * Some SD/TF cards on the Elecrow 7" board reject CMD59 with
 * ESP_ERR_NOT_SUPPORTED, which causes the ESP-IDF SPI SD driver to
 * abort the whole init sequence.
 *
 * This link-time wrap intercepts sdmmc_init_spi_crc:
 *   - Calls the real function first.
 *   - If it returns ESP_ERR_NOT_SUPPORTED, issues a best-effort
 *     CMD59(off) directly via the host transaction callback, then
 *     returns ESP_OK so that init continues without CRC.
 *
 * Enabled by linker flags in main/CMakeLists.txt:
 *   -Wl,--wrap=sdmmc_init_spi_crc
 *   -Wl,--undefined=__wrap_sdmmc_init_spi_crc
 *
 * This matches Arduino SD library behaviour (data CRC disabled).
 */

#ifdef USE_LCD_RGB_ELECROW7S3

#include <string.h>
#include "esp_err.h"
#include "esp_log.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"

static const char *TAG = "sdmmc_crc_wrap";

/* Declaration of the real (unwrapped) function provided by the linker */
esp_err_t __real_sdmmc_init_spi_crc(sdmmc_card_t *card);

esp_err_t __wrap_sdmmc_init_spi_crc(sdmmc_card_t *card)
{
	esp_err_t ret = __real_sdmmc_init_spi_crc(card);
	if (ret == ESP_ERR_NOT_SUPPORTED) {
		ESP_LOGW(TAG, "CMD59 not supported, disabling CRC and continuing");
		/*
		 * Best-effort CMD59(off) via the host's do_transaction callback.
		 * If this also fails we still return ESP_OK so that the SD init
		 * can proceed (matching Arduino SD library behaviour).
		 */
		sdmmc_command_t cmd = {
			.opcode   = 59,   /* CMD59: CRC_ON_OFF */
			.arg      = 0,    /* 0 = CRC off */
			.flags    = SCF_CMD_AC | SCF_RSP_R1,
		};
		card->host.do_transaction(card->host.slot, &cmd);
		return ESP_OK;
	}
	return ret;
}

#endif /* USE_LCD_RGB_ELECROW7S3 */
