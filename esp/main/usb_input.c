/*
 * SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp_err.h"
#include "esp_log.h"
#include "usb/usb_host.h"
#include "errno.h"
#include "driver/gpio.h"

#include "common.h"
#include "../../i8042.h"

#include "usb/hid_host.h"
#include "usb/hid_usage_keyboard.h"
#include "usb/hid_usage_mouse.h"

int hid_usage_to_ps2input(int hid);
const char *hid_usage_to_name(uint8_t code);
int hid_usage_to_linux_keycode(int hid);

static const char *TAG = "example";
void usb_task(void *arg);

static const uint8_t modifier_to_hid_usage[8] = {
    0xE0, // bit 0 left_ctr
    0xE1, // bit 1 left_shift
    0xE2, // bit 2 left_alt
    0xE3, // bit 3 left_gui
    0xE4, // bit 4 right_ctr
    0xE5, // bit 5 right_shift
    0xE6, // bit 6 right_alt
    0xE7  // bit 7 right_gui
};

QueueHandle_t app_event_queue = NULL;

/**
 * @brief APP event group
 *
 * Application logic can be different. There is a one among other ways to distinguish the
 * event by application event group.
 * In this example we have two event groups:
 * APP_EVENT            - General event, which is APP_QUIT_PIN press event (Generally, it is IO0).
 * APP_EVENT_HID_HOST   - HID Host Driver event, such as device connection/disconnection or input report.
 */
typedef enum
{
    APP_EVENT = 0,
    APP_EVENT_HID_HOST
} app_event_group_t;

/**
 * @brief APP event queue
 *
 * This event is used for delivering the HID Host event from callback to a task.
 */
typedef struct
{
    app_event_group_t event_group;
    /* HID Host - Device related info */
    struct
    {
        hid_host_device_handle_t handle;
        hid_host_driver_event_t event;
        void *arg;
    } hid_host_device;
} app_event_queue_t;

/**
 * @brief HID Protocol string names
 */
static const char *hid_proto_name_str[] = {
    "NONE",
    "KEYBOARD",
    "MOUSE"};

/**
 * @brief Key event
 */
typedef struct
{
    enum key_state
    {
        KEY_STATE_PRESSED = 0x00,
        KEY_STATE_RELEASED = 0x01
    } state;
    uint8_t modifier;
    uint8_t key_code;
} key_event_t;

/**
 * @brief Key buffer scan code search.
 *
 * @param[in] src       Pointer to source buffer where to search
 * @param[in] key       Key scancode to search
 * @param[in] length    Size of the source buffer
 */
static inline bool key_found(const uint8_t *const src,
                             uint8_t key,
                             unsigned int length)
{
    for (unsigned int i = 0; i < length; i++)
    {
        if (src[i] == key)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief USB HID Host Keyboard Interface report callback handler
 *
 * @param[in] data    Pointer to input report data buffer
 * @param[in] length  Length of input report data buffer
 */
static void hid_host_keyboard_report_callback(const uint8_t *const data, const int length)
{
    hid_keyboard_input_report_boot_t *kb_report = (hid_keyboard_input_report_boot_t *)data;

    if (length < sizeof(hid_keyboard_input_report_boot_t))
    {
        return;
    }

    static uint8_t prev_keys[HID_KEYBOARD_KEY_MAX] = {0};
    static uint8_t prev_mod[8] = {0};

    key_event_t key_event;

    uint8_t mod = kb_report->modifier.val;

    for (int bit = 0; bit < 8; bit++)
    {

        uint8_t is_down = (mod >> bit) & 1;
        uint8_t was_down = prev_mod[bit];

        if (is_down != was_down)
        {

            uint8_t hid_code = modifier_to_hid_usage[bit];

            key_event.key_code = hid_code;
            key_event.modifier = mod;
            key_event.state = is_down ? KEY_STATE_PRESSED : KEY_STATE_RELEASED;

            // key_event_callback(&key_event);
            int ps2code = hid_usage_to_ps2input(hid_code);
            int linuxCode = hid_usage_to_linux_keycode(hid_code);
            ps2_put_keycode(globals.kbd, is_down, linuxCode);

            // ESP_LOGE("HID",
            //          "MOD EVENT: %s HID=%02X (%s)  PS2=0x%X  Linux=%d",
            //          is_down ? "DOWN" : "UP",
            //          hid_code,
            //          hid_usage_to_name(hid_code),
            //          ps2code, linuxCode);
        }

        prev_mod[bit] = is_down;
    }
    for (int i = 0; i < HID_KEYBOARD_KEY_MAX; i++)
    {

        // key has been released verification
        if (prev_keys[i] > HID_KEY_ERROR_UNDEFINED &&
            !key_found(kb_report->key, prev_keys[i], HID_KEYBOARD_KEY_MAX))
        {
            key_event.key_code = prev_keys[i];
            key_event.modifier = 0;
            key_event.state = KEY_STATE_RELEASED;
            // key_event_callback(&key_event);
            int ps2code = hid_usage_to_ps2input(prev_keys[i]);
            int linuxCode = hid_usage_to_linux_keycode(prev_keys[i]);
            ps2_put_keycode(globals.kbd, false, linuxCode);
            // ESP_LOGE("HID",
            //          "RELEASE EVENT: HID=%02X (%s)  PS2=0x%X   Linux=%d",
            //          prev_keys[i],
            //          hid_usage_to_name(prev_keys[i]),
            //          ps2code, linuxCode);
        }

        // key has been pressed verification
        if (kb_report->key[i] > HID_KEY_ERROR_UNDEFINED &&
            !key_found(prev_keys, kb_report->key[i], HID_KEYBOARD_KEY_MAX))
        {
            key_event.key_code = kb_report->key[i];
            key_event.modifier = kb_report->modifier.val;
            key_event.state = KEY_STATE_PRESSED;

            int ps2code = hid_usage_to_ps2input(kb_report->key[i]);
            int linuxCode = hid_usage_to_linux_keycode(kb_report->key[i]);
            ps2_put_keycode(globals.kbd, true, linuxCode);
            // ESP_LOGE("HID",
            //          "PRESS EVENT: HID=%02X (%s)  PS2=0x%X   Linux=%d",
            //          kb_report->key[i],
            //          hid_usage_to_name(kb_report->key[i]),
            //          ps2code, linuxCode);
        }
    }

    memcpy(prev_keys, &kb_report->key, HID_KEYBOARD_KEY_MAX);
}

/**
 * @brief USB HID Host Mouse Interface report callback handler
 *
 * @param[in] data    Pointer to input report data buffer
 * @param[in] length  Length of input report data buffer
 */
static void hid_host_mouse_report_callback(const uint8_t *const data, const int length)
{
    hid_mouse_input_report_boot_t *mouse_report = (hid_mouse_input_report_boot_t *)data;

    if (length < sizeof(hid_mouse_input_report_boot_t))
    {
        return;
    }

    static int x_pos = 0;
    static int y_pos = 0;

    // Calculate absolute position from displacement
    x_pos += mouse_report->x_displacement;
    y_pos += mouse_report->y_displacement;

    int dx = mouse_report->x_displacement;
    int dy = mouse_report->y_displacement;

    /* Convert HID button bits → PS/2 button state */
    int buttons = 0;

    if (mouse_report->buttons.button1)
        buttons |= 1; // Left button bit
    if (mouse_report->buttons.button2)
        buttons |= 2; // Right button bit
    if (mouse_report->buttons.button3)
        buttons |= 4; // Middle button bit

    /* No wheel for HID boot mouse */
    int dz = 0;

    /* Send to emulator */
    ps2_mouse_event(globals.mouse, dx, dy, dz, buttons);

    // ESP_LOGE("HID-MOUSE",
    //          "Mouse HID:  dx=%4d  dy=%4d  | L=%d M=%d R=%d |\n"
    //          "Mouse PS2:  dx=%4d  dy=%4d  dz=%2d  btn=0x%02X\n",
    //          mouse_report->x_displacement,
    //          mouse_report->y_displacement,
    //          mouse_report->buttons.button1,
    //          mouse_report->buttons.button3,
    //          mouse_report->buttons.button2,
    //          dx, dy, dz, buttons);

   
    fflush(stdout);
}

/**
 * @brief USB HID Host interface callback
 *
 * @param[in] hid_device_handle  HID Device handle
 * @param[in] event              HID Host interface event
 * @param[in] arg                Pointer to arguments, does not used
 */
void hid_host_interface_callback(hid_host_device_handle_t hid_device_handle,
                                 const hid_host_interface_event_t event,
                                 void *arg)
{
    uint8_t data[64] = {0};
    size_t data_length = 0;
    hid_host_dev_params_t dev_params;
    ESP_ERROR_CHECK(hid_host_device_get_params(hid_device_handle, &dev_params));

    switch (event)
    {
    case HID_HOST_INTERFACE_EVENT_INPUT_REPORT:
        ESP_ERROR_CHECK(hid_host_device_get_raw_input_report_data(hid_device_handle,
                                                                  data,
                                                                  64,
                                                                  &data_length));

        if (HID_SUBCLASS_BOOT_INTERFACE == dev_params.sub_class)
        {
            if (HID_PROTOCOL_KEYBOARD == dev_params.proto)
            {
                hid_host_keyboard_report_callback(data, data_length);
            }
            else if (HID_PROTOCOL_MOUSE == dev_params.proto)
            {
                hid_host_mouse_report_callback(data, data_length);
            }
        }

        break;
    case HID_HOST_INTERFACE_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "HID Device, protocol '%s' DISCONNECTED",
                 hid_proto_name_str[dev_params.proto]);
        ESP_ERROR_CHECK(hid_host_device_close(hid_device_handle));
        break;
    case HID_HOST_INTERFACE_EVENT_TRANSFER_ERROR:
        ESP_LOGI(TAG, "HID Device, protocol '%s' TRANSFER_ERROR",
                 hid_proto_name_str[dev_params.proto]);
        break;
    default:
        ESP_LOGE(TAG, "HID Device, protocol '%s' Unhandled event",
                 hid_proto_name_str[dev_params.proto]);
        break;
    }
}

/**
 * @brief USB HID Host Device event
 *
 * @param[in] hid_device_handle  HID Device handle
 * @param[in] event              HID Host Device event
 * @param[in] arg                Pointer to arguments, does not used
 */
void hid_host_device_event(hid_host_device_handle_t hid_device_handle,
                           const hid_host_driver_event_t event,
                           void *arg)
{
    hid_host_dev_params_t dev_params;
    ESP_ERROR_CHECK(hid_host_device_get_params(hid_device_handle, &dev_params));

    switch (event)
    {
    case HID_HOST_DRIVER_EVENT_CONNECTED:
        ESP_LOGI(TAG, "HID Device, protocol '%s' CONNECTED",
                 hid_proto_name_str[dev_params.proto]);

        const hid_host_device_config_t dev_config = {
            .callback = hid_host_interface_callback,
            .callback_arg = NULL};

        if (dev_params.proto != HID_PROTOCOL_NONE)
        {
            ESP_ERROR_CHECK(hid_host_device_open(hid_device_handle, &dev_config));
            if (HID_SUBCLASS_BOOT_INTERFACE == dev_params.sub_class)
            {
                ESP_ERROR_CHECK(hid_class_request_set_protocol(hid_device_handle, HID_REPORT_PROTOCOL_BOOT));
                if (HID_PROTOCOL_KEYBOARD == dev_params.proto)
                {
                    ESP_ERROR_CHECK(hid_class_request_set_idle(hid_device_handle, 0, 0));
                }
            }
            ESP_ERROR_CHECK(hid_host_device_start(hid_device_handle));
        }
        break;
    default:
        break;
    }
}

/**
 * @brief Start USB Host install and handle common USB host library events while app pin not low
 *
 * @param[in] arg  Not used
 */
static void usb_lib_task(void *arg)
{
    const usb_host_config_t host_config = {
        .skip_phy_setup = false,
        .intr_flags = ESP_INTR_FLAG_LOWMED,
    };

    ESP_ERROR_CHECK(usb_host_install(&host_config));
    xTaskNotifyGive(arg);

    while (true)
    {
        uint32_t event_flags;
        usb_host_lib_handle_events(portMAX_DELAY, &event_flags);
        // In this example, there is only one client registered
        // So, once we deregister the client, this call must succeed with ESP_OK
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS)
        {
            ESP_ERROR_CHECK(usb_host_device_free_all());
            break;
        }
    }

    ESP_LOGI(TAG, "USB shutdown");
    // Clean up USB Host
    vTaskDelay(10); // Short delay to allow clients clean-up
    ESP_ERROR_CHECK(usb_host_uninstall());
    vTaskDelete(NULL);
}

/**
 * @brief BOOT button pressed callback
 *
 * Signal application to exit the HID Host task
 *
 * @param[in] arg Unused
 */
static void gpio_isr_cb(void *arg)
{
    BaseType_t xTaskWoken = pdFALSE;
    const app_event_queue_t evt_queue = {
        .event_group = APP_EVENT,
    };

    if (app_event_queue)
    {
        xQueueSendFromISR(app_event_queue, &evt_queue, &xTaskWoken);
    }

    if (xTaskWoken == pdTRUE)
    {
        portYIELD_FROM_ISR();
    }
}

/**
 * @brief HID Host Device callback
 *
 * Puts new HID Device event to the queue
 *
 * @param[in] hid_device_handle HID Device handle
 * @param[in] event             HID Device event
 * @param[in] arg               Not used
 */
void hid_host_device_callback(hid_host_device_handle_t hid_device_handle,
                              const hid_host_driver_event_t event,
                              void *arg)
{
    const app_event_queue_t evt_queue = {
        .event_group = APP_EVENT_HID_HOST,
        // HID Host Device related info
        .hid_host_device.handle = hid_device_handle,
        .hid_host_device.event = event,
        .hid_host_device.arg = arg};

    if (app_event_queue)
    {
        xQueueSend(app_event_queue, &evt_queue, 0);
    }
}

void usb_setup(void)
{
    BaseType_t task_created;

    ESP_LOGI(TAG, "HID Host example");

    /*
     * Create usb_lib_task to:
     * - initialize USB Host library
     * - Handle USB Host events while APP pin in in HIGH state
     */
    task_created = xTaskCreatePinnedToCore(usb_lib_task,
                                           "usb_events",
                                           4096,
                                           xTaskGetCurrentTaskHandle(),
                                           2, NULL, 0);
    assert(task_created == pdTRUE);

    // Wait for notification from usb_lib_task to proceed
    ulTaskNotifyTake(false, 1000);

    /*
     * HID host driver configuration
     * - create background task for handling low level event inside the HID driver
     * - provide the device callback to get new HID Device connection event
     */
    const hid_host_driver_config_t hid_host_driver_config = {
        .create_background_task = true,
        .task_priority = 5,
        .stack_size = 4096,
        .core_id = 0,
        .callback = hid_host_device_callback,
        .callback_arg = NULL};

    ESP_ERROR_CHECK(hid_host_install(&hid_host_driver_config));

    // Create queue
    app_event_queue = xQueueCreate(10, sizeof(app_event_queue_t));

    ESP_LOGI(TAG, "Waiting for HID Device to be connected");

    xTaskCreatePinnedToCore(usb_task, "usb_task", 4096, NULL, 0, NULL, 0);
}
void usb_task(void *arg)
{
    app_event_queue_t evt_queue;
    while (1)
    {
        // Wait queue
        if (xQueueReceive(app_event_queue, &evt_queue, portMAX_DELAY))
        {

            if (APP_EVENT_HID_HOST == evt_queue.event_group)
            {
                hid_host_device_event(evt_queue.hid_host_device.handle,
                                      evt_queue.hid_host_device.event,
                                      evt_queue.hid_host_device.arg);
            }
        }
    }
}
