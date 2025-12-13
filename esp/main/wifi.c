/* Simple WiFi Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <stdatomic.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_private/wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include <sys/socket.h>

#include "common.h"
#include "../../i8042.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_MAX_STA_CONN       CONFIG_MAX_STA_CONN

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SAE_MODE WPA3_SAE_PWE_HUNT_AND_PECK
#define EXAMPLE_H2E_IDENTIFIER ""

static const char *TAG = "simple wifi";

void (*_Atomic esp32_send_packet)(uint8_t *buf, int size);

static void send_packet(uint8_t *buf, int size)
{
	esp_wifi_internal_tx(ESP_IF_WIFI_STA, buf, size);
}

static void event_handler(void* arg, esp_event_base_t event_base,
			  int32_t event_id, void* event_data)
{
	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		esp_wifi_connect();
		ESP_LOGI(TAG, "retry to connect to the AP");
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	}

	if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		atomic_store_explicit(&esp32_send_packet, NULL,
				      memory_order_relaxed);
	} else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
		atomic_store_explicit(&esp32_send_packet, send_packet,
				      memory_order_relaxed);
	}
}

void wifi_init_sta(const char *ssid, const char *pass)
{
	s_wifi_event_group = xEventGroupCreate();

	ESP_ERROR_CHECK(esp_netif_init());

	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id;
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
							    ESP_EVENT_ANY_ID,
							    &event_handler,
							    NULL,
							    &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
							    IP_EVENT_STA_GOT_IP,
							    &event_handler,
							    NULL,
							    &instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = {
			/* Authmode threshold resets to WPA2 as default if password matches WPA2 standards (pasword len => 8).
			 * If you want to connect the device to deprecated WEP/WPA networks, Please set the threshold value
			 * to WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK and set the password with length and format matching to
			 * WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK standards.
			 */
			.threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
			.sae_pwe_h2e = ESP_WIFI_SAE_MODE,
			.sae_h2e_identifier = EXAMPLE_H2E_IDENTIFIER,
		},
	};
	if (strlen(ssid) < 32 && strlen(pass) < 64) {
		strcpy((char *) wifi_config.sta.ssid, ssid);
		strcpy((char *) wifi_config.sta.password, pass);
	} else {
		ESP_LOGE(TAG, "ssid or password is too long");
		return;
	}
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
	ESP_ERROR_CHECK(esp_wifi_start() );

	ESP_LOGI(TAG, "wifi_init_sta finished.");

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
	 * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
					       WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
					       pdFALSE,
					       pdFALSE,
					       portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
	 * happened. */
	if (bits & WIFI_CONNECTED_BIT) {
		ESP_LOGI(TAG, "connected to ap SSID:%s", ssid);
	} else if (bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s", ssid);
	} else {
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
	}
}

static void __attribute__((noreturn)) task_fatal_error()
{
	ESP_LOGE(TAG, "Exiting task due to fatal error...");
	(void)vTaskDelete(NULL);

	while (1) {
		;
	}
}

static void server_thread(void *pvParameter)
{
	struct sockaddr_in sock_info;

	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd == -1) {
		ESP_LOGE(TAG, "Create socket failed!");
		return;
	}

	memset(&sock_info, 0, sizeof(struct sockaddr_in));
	sock_info.sin_family = AF_INET;
	sock_info.sin_addr.s_addr = htonl(INADDR_ANY);
	sock_info.sin_port = htons(9999);

	if(bind(sfd, (struct sockaddr *)&sock_info, sizeof(sock_info)) < 0)
		task_fatal_error();

	if(listen(sfd, 10) < 0)
		task_fatal_error();

	for (;;) {
		static int state;
		static int8_t mouse[4];

		int socket_id = accept(sfd, NULL, 0);
		state = 0;
		xEventGroupWaitBits(global_event_group,
				    BIT0,
				    pdFALSE,
				    pdFALSE,
				    portMAX_DELAY);

		bool flag = true;
		char text[16];
		while (flag) {
			int buff_len = recv(socket_id, text, 16, 0);
			if (buff_len < 0) { /*receive error*/
				ESP_LOGE(TAG, "Error: receive data error! errno=%d", errno);
				flag = false;
				close(socket_id);
			} else if (buff_len > 0) { /*deal with response body*/
				for (int i = 0; i < buff_len; i++) {
					if (state == 0) {
						if (text[i] == 0) {
							state = 4;
						} else {
							int is_down = !(text[i] >> 7);
							int keycode = text[i] & 0x7f;
							ps2_put_keycode(globals.kbd, is_down, keycode);
							vTaskDelay(5 / portTICK_PERIOD_MS);
						}
					} else {
						mouse[4 - state] = text[i];
						if (state == 1) {
							state = 0;
							ps2_mouse_event(globals.mouse,
									mouse[0], mouse[1], mouse[2], mouse[3]);
							vTaskDelay(5 / portTICK_PERIOD_MS);
						} else {
							state--;
						}
					}
				}
			} else if (buff_len == 0) {  /*packet over*/
				ESP_LOGI(TAG, "Connection closed, all packets received");
				flag = false;
				close(socket_id);
			}
		}
	}
}

void wifi_main(const char *ssid, const char *pass)
{
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);
	wifi_init_sta(ssid, pass);
	xTaskCreatePinnedToCore(server_thread, "wifi", 4096, NULL, 1, NULL, 0);
}
