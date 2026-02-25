// requires esp-idf v5.5.x and sdkconfig.esp32p4
#define PSRAM_ALLOC_LEN (10 * 1024 * 1024)

#define BPP 16
#define FULL_UPDATE
#define SWAPXY
#define USE_LCD_ST7701
#define LCD_WIDTH 800
#define LCD_HEIGHT 480

// XXX: SD card doesn't work now
#define SD_CLK 43
#define SD_CMD 44
#define SD_D0 39
#define SD_D1 40
#define SD_D2 41
#define SD_D3 42

// TODO: I2S
