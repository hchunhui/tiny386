// requires esp-idf v6.0.x
#define BUILD_ESP32

#define PSRAM_ALLOC_LEN (10 * 1024 * 1024)

// XXX: ld reports "error: Total discarded sections size is X bytes"
//#define IRAM_ATTR_CPU_EXEC1 IRAM_ATTR
#define IRAM_ATTR_CPU_EXEC1

#define BPP 16
#define FULL_UPDATE
#define SWAPXY
#define USE_LCD_ST7701
#define LCD_WIDTH 800
#define LCD_HEIGHT 480

#define SD_CLK 43
#define SD_CMD 44
#define SD_D0 39
#define SD_D1 40
#define SD_D2 41
#define SD_D3 42
#define SD_PWR_CTRL_LDO_IO_ID 4

#define USE_HOSTED_WIFI

// TODO: I2S
