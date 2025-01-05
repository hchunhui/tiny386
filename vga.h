#ifndef VGA_H
#define VGA_H

typedef struct FBDevice FBDevice;

typedef void SimpleFBDrawFunc(FBDevice *fb_dev, void *opaque,
                              int x, int y, int w, int h);

struct FBDevice {
    /* the following is set by the device */
    int width;
    int height;
    int stride; /* current stride in bytes */
    uint8_t *fb_data; /* current pointer to the pixel data */
    int fb_size; /* frame buffer memory size (info only) */
    void *device_opaque;
    void (*refresh)(struct FBDevice *fb_dev,
                    SimpleFBDrawFunc *redraw_func, void *opaque);
};


typedef struct VGAState VGAState;
VGAState *vga_init(FBDevice *fb_dev,
		   int width, int height,
		   const uint8_t *vga_rom_buf, int vga_rom_size, uint8_t *vga_ram);

void vga_ioport_write(VGAState *s, uint32_t addr, uint32_t val);
uint32_t vga_ioport_read(VGAState *s, uint32_t addr);

void vga_mem_write(VGAState *s, uint32_t addr, uint8_t val);
uint8_t vga_mem_read(VGAState *s, uint32_t addr);

#endif /* VGA_H */
