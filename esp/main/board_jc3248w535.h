#define BUILD_ESP32

#define IRAM_ATTR_CPU_EXEC1 IRAM_ATTR

#define BPP 16
#define SCALE_3_2
#define FULL_UPDATE
#define SWAPXY
#define SWAP_BYTEORDER_BPP16
#define USE_LCD_AXS15231B
#define LCD_WIDTH 480
#define LCD_HEIGHT 320

#define SD_CLK 12
#define SD_CMD 11
#define SD_D0 13

#define I2S_MCLK I2S_GPIO_UNUSED
#define I2S_BCLK 42
#define I2S_WS   2
#define I2S_DOUT 41
