#define BUILD_ESP32

#define IRAM_ATTR_CPU_EXEC1 IRAM_ATTR

#define BPP 16
#define FULL_UPDATE
// No SWAPXY — 800x480 landscape matches VGA output directly
#define USE_LCD_RGB_ELECROW7S3
#define LCD_WIDTH  800
#define LCD_HEIGHT 480

// PSRAM bump-allocator pool (guest RAM 6 MB + overhead)
#define PSRAM_ALLOC_LEN (int)(6.5 * 1024 * 1024)

// SD card: SPI mode via SPI2_HOST
#define SD_SPI_MOSI  6
#define SD_SPI_MISO  4
#define SD_SPI_SCK   5
#define SD_SPI_CS    0
#define SD_SPI_FREQ_KHZ 10000

// I2C for backlight (CH422G I/O expander)
#define LCD_I2C_SDA  15
#define LCD_I2C_SCL  16

// No I2S audio — GPIO conflicts with RGB data bus
