/*
 * JS/Linux Linux starter
 *
 * Copyright (c) 2011 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "libc.h"
#include "linuxstart.h"

/* from plex86 (BSD license) */
struct  __attribute__ ((packed)) linux_params {
  // For 0x00..0x3f, see 'struct screen_info' in linux/include/linux/tty.h.
  // I just padded out the VESA parts, rather than define them.

  /* 0x000 */ uint8_t   orig_x;
  /* 0x001 */ uint8_t   orig_y;
  /* 0x002 */ uint16_t  ext_mem_k;
  /* 0x004 */ uint16_t  orig_video_page;
  /* 0x006 */ uint8_t   orig_video_mode;
  /* 0x007 */ uint8_t   orig_video_cols;
  /* 0x008 */ uint16_t  unused1;
  /* 0x00a */ uint16_t  orig_video_ega_bx;
  /* 0x00c */ uint16_t  unused2;
  /* 0x00e */ uint8_t   orig_video_lines;
  /* 0x00f */ uint8_t   orig_video_isVGA;
  /* 0x010 */ uint16_t  orig_video_points;
  // The linear frame buffer (orig_video_isVGA == VIDEO_TYPE_VLFB).
  /* 0x012 */ uint16_t  lfb_width;
  /* 0x014 */ uint16_t  lfb_height;
  /* 0x016 */ uint16_t  lfb_depth;
  /* 0x018 */ uint32_t  lfb_base;
  /* 0x01c */ uint32_t  lfb_size;  // in 64 KB units
  /* 0x020 */ uint16_t  cl_magic;  // Commandline magic number (0xA33F)
  /* 0x022 */ uint16_t  cl_offset; // Commandline offset.  Address of commandline
                                 // is calculated as 0x90000 + cl_offset, bu
                                 // only if cl_magic == 0xA33F.
  /* 0x024 */ uint16_t  lfb_linelength;
  /* 0x026 */ uint8_t   red_size, red_pos, green_size, green_pos;
  /* 0x02a */ uint8_t   blue_size, blue_pos, rsvd_size, rsvd_pos;
  /* 0x02e */ uint16_t  vesapm_seg, vesapm_off;
  /* 0x032 */ uint16_t  pages;
  /* 0x034 */ uint8_t   pad1[0x40 - 0x34]; // VESA info.

  /* 0x040 */ uint8_t   apm_bios_info[20]; // struct apm_bios_info
  /* 0x054 */ uint8_t   pad2[0x80 - 0x54];

  // Following 2 from 'struct drive_info_struct' in drivers/block/cciss.h.
  // Might be truncated?
  /* 0x080 */ uint8_t   hd0_info[16]; // hd0-disk-parameter from intvector 0x41
  /* 0x090 */ uint8_t   hd1_info[16]; // hd1-disk-parameter from intvector 0x46

  // System description table truncated to 16 bytes
  // From 'struct sys_desc_table_struct' in linux/arch/i386/kernel/setup.c.
  /* 0x0a0 */ uint16_t  sys_description_len;
  /* 0x0a2 */ uint8_t   sys_description_table[14];
                        // [0] machine id
                        // [1] machine submodel id
                        // [2] BIOS revision
                        // [3] bit1: MCA bus

  /* 0x0b0 */ uint8_t   pad3[0x1e0 - 0xb0];
  /* 0x1e0 */ uint32_t  alt_mem_k;
  /* 0x1e4 */ uint8_t   pad4[4];
  /* 0x1e8 */ uint8_t   e820map_entries;
  /* 0x1e9 */ uint8_t   eddbuf_entries; // EDD_NR
  /* 0x1ea */ uint8_t   pad5[0x1f1 - 0x1ea];
  /* 0x1f1 */ uint8_t   setup_sects; // size of setup.S, number of sectors
  /* 0x1f2 */ uint16_t  mount_root_rdonly; // MOUNT_ROOT_RDONLY (if !=0)
  /* 0x1f4 */ uint16_t  sys_size; // size of compressed kernel-part in the
                                // (b)zImage-file (in 16 byte units, rounded up)
  /* 0x1f6 */ uint16_t  swap_dev; // (unused AFAIK)
  /* 0x1f8 */ uint16_t  ramdisk_flags;
  /* 0x1fa */ uint16_t  vga_mode; // (old one)
  /* 0x1fc */ uint16_t  orig_root_dev; // (high=Major, low=minor)
  /* 0x1fe */ uint8_t   pad6[1];
  /* 0x1ff */ uint8_t   aux_device_info;
  /* 0x200 */ uint16_t  jump_setup; // Jump to start of setup code,
                                  // aka "reserved" field.
  /* 0x202 */ uint8_t   setup_signature[4]; // Signature for SETUP-header, ="HdrS"
  /* 0x206 */ uint16_t  header_format_version; // Version number of header format;
  /* 0x208 */ uint8_t   setup_S_temp0[8]; // Used by setup.S for communication with
                                        // boot loaders, look there.
  /* 0x210 */ uint8_t   loader_type;
                        // 0 for old one.
                        // else 0xTV:
                        //   T=0: LILO
                        //   T=1: Loadlin
                        //   T=2: bootsect-loader
                        //   T=3: SYSLINUX
                        //   T=4: ETHERBOOT
                        //   V=version
  /* 0x211 */ uint8_t   loadflags;
                        // bit0 = 1: kernel is loaded high (bzImage)
                        // bit7 = 1: Heap and pointer (see below) set by boot
                        //   loader.
  /* 0x212 */ uint16_t  setup_S_temp1;
  /* 0x214 */ uint32_t  kernel_start;
  /* 0x218 */ uint32_t  initrd_start;
  /* 0x21c */ uint32_t  initrd_size;
  /* 0x220 */ uint8_t   setup_S_temp2[4];
  /* 0x224 */ uint16_t  setup_S_heap_end_pointer;
  /* 0x226 */ uint16_t  pad70;
  /* 0x228 */ uint32_t  cmd_line_ptr;
  /* 0x22c */ uint8_t   pad7[0x2d0 - 0x22c];

  /* 0x2d0 : Int 15, ax=e820 memory map. */
  // (linux/include/asm-i386/e820.h, 'struct e820entry')
#define E820MAX  32
#define E820_RAM  1
#define E820_RESERVED 2
#define E820_ACPI 3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS  4
  struct {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
  } __attribute__((packed)) e820map[E820MAX];

  /* 0x550 */ uint8_t   pad8[0x600 - 0x550];

  // BIOS Enhanced Disk Drive Services.
  // (From linux/include/asm-i386/edd.h, 'struct edd_info')
  // Each 'struct edd_info is 78 bytes, times a max of 6 structs in array.
  /* 0x600 */ uint8_t   eddbuf[0x7d4 - 0x600];

  /* 0x7d4 */ uint8_t   pad9[0x800 - 0x7d4];
  /* 0x800 */ uint8_t   commandline[0x800];

  /* 0x1000 */
  uint64_t gdt_table[256];
  uint64_t idt_table[48];
};

/*
 * A graphics mode for the kernel's VESA frame buffer driver (vesafb), when the
 * command line asks for one with vga=<mode> (a VESA mode number + 0x200, as
 * for other boot loaders: 0x301/0x303/0x305 640x480/800x600/1024x768 with 256
 * colours, 0x311/0x314/0x317 the same with 16-bit colour, 0x312/0x315/0x318
 * 24-bit; see the table below). No BIOS has run, so the mode is set through
 * the Bochs VBE interface, the VGA's PCI BAR 0 is mapped if it isn't, and the
 * linear frame buffer is described to the kernel in screen_info. Without vga=,
 * or a mode the display can't show (video memory, the largest resolution),
 * text mode stays.
 */
#define VBE_DISPI_INDEX_ID          0
#define VBE_DISPI_INDEX_XRES        1
#define VBE_DISPI_INDEX_YRES        2
#define VBE_DISPI_INDEX_BPP         3
#define VBE_DISPI_INDEX_ENABLE      4
#define VBE_DISPI_INDEX_VIRT_WIDTH  6
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 10
#define VBE_DISPI_ENABLED           0x01
#define VBE_DISPI_GETCAPS           0x02
#define VBE_DISPI_LFB_ENABLED       0x40
#define VBE_DISPI_NOCLEARMEM        0x80
#define VIDEO_TYPE_VLFB             0x23
#define LFB_DEFAULT_BASE            0xe0000000u

static const struct { uint16_t mode, w, h; uint8_t bpp; } vesa_modes[] = {
    { 0x301,  640,  480,  8 }, { 0x303,  800,  600,  8 },
    { 0x305, 1024,  768,  8 }, { 0x307, 1280, 1024,  8 },
    { 0x310,  640,  480, 15 }, { 0x311,  640,  480, 16 },
    { 0x312,  640,  480, 24 }, { 0x313,  800,  600, 15 },
    { 0x314,  800,  600, 16 }, { 0x315,  800,  600, 24 },
    { 0x316, 1024,  768, 15 }, { 0x317, 1024,  768, 16 },
    { 0x318, 1024,  768, 24 }, { 0x319, 1280, 1024, 15 },
    { 0x31a, 1280, 1024, 16 }, { 0x31b, 1280, 1024, 24 },
};

static inline void io_outw(uint16_t port, uint16_t v)
{
    asm volatile ("outw %0, %1" : : "a" (v), "Nd" (port));
}

static inline uint16_t io_inw(uint16_t port)
{
    uint16_t v;
    asm volatile ("inw %1, %0" : "=a" (v) : "Nd" (port));
    return v;
}

static inline void io_outb(uint16_t port, uint8_t v)
{
    asm volatile ("outb %0, %1" : : "a" (v), "Nd" (port));
}

static inline uint8_t io_inb(uint16_t port)
{
    uint8_t v;
    asm volatile ("inb %1, %0" : "=a" (v) : "Nd" (port));
    return v;
}

static inline void io_outl(uint16_t port, uint32_t v)
{
    asm volatile ("outl %0, %1" : : "a" (v), "Nd" (port));
}

static inline uint32_t io_inl(uint16_t port)
{
    uint32_t v;
    asm volatile ("inl %1, %0" : "=a" (v) : "Nd" (port));
    return v;
}

static void dispi_set(int index, int val)
{
    io_outw(0x1ce, index);
    io_outw(0x1cf, val);
}

static int dispi_get(int index)
{
    io_outw(0x1ce, index);
    return io_inw(0x1cf);
}

static uint32_t pci_read(int devfn, int reg)
{
    io_outl(0xcf8, 0x80000000u | devfn << 8 | reg);
    return io_inl(0xcfc);
}

static void pci_write(int devfn, int reg, uint32_t val)
{
    io_outl(0xcf8, 0x80000000u | devfn << 8 | reg);
    io_outl(0xcfc, val);
}

/*
 * The VGA registers enabling a VBE mode changes (graphics, chain 4, the
 * CRTC's timing), kept to put text mode back if the mode isn't usable.
 */
static const struct { uint16_t port; uint8_t index; } vga_saved[] = {
    { 0x3c4, 0x01 }, { 0x3c4, 0x02 }, { 0x3c4, 0x04 },
    { 0x3ce, 0x05 }, { 0x3ce, 0x06 },
    { 0x3d4, 0x01 }, { 0x3d4, 0x07 }, { 0x3d4, 0x09 }, { 0x3d4, 0x12 },
    { 0x3d4, 0x13 }, { 0x3d4, 0x17 }, { 0x3d4, 0x18 },
};
#define VGA_SAVED (sizeof(vga_saved) / sizeof(vga_saved[0]))

static void vga_save(uint8_t *v)
{
    for (int i = 0; i < VGA_SAVED; i++) {
        io_outb(vga_saved[i].port, vga_saved[i].index);
        v[i] = io_inb(vga_saved[i].port + 1);
    }
}

static void vga_restore(const uint8_t *v)
{
    io_outb(0x3d4, 0x11);   /* CRTC registers 0-7 writable meanwhile */
    uint8_t protect = io_inb(0x3d5);
    io_outb(0x3d5, protect & 0x7f);
    for (int i = 0; i < VGA_SAVED; i++) {
        io_outb(vga_saved[i].port, vga_saved[i].index);
        io_outb(vga_saved[i].port + 1, v[i]);
    }
    io_outb(0x3d4, 0x11);
    io_outb(0x3d5, protect);
}

/* the command register alone (the status register above it clears bits written as 1) */
static void pci_command_set(int devfn, uint16_t bits)
{
    io_outl(0xcf8, 0x80000000u | devfn << 8 | 0x04);
    io_outw(0xcfc, io_inw(0xcfc) | bits);
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/*
 * The mode vga= asks for: a number, decimal or 0x hexadecimal; the last vga=
 * counts, as in the kernel's own boot code. 0: none, or not a number (such as
 * vga=normal or vga=ask), or too large.
 */
static int vga_mode(const char *cmdline)
{
    const char *p = cmdline;
    int mode = 0;
    while (*p) {
        if ((p == cmdline || is_space(p[-1])) && p[0] == 'v' && p[1] == 'g' && p[2] == 'a' && p[3] == '=') {
            p += 4;
            int base = 10, v = 0, ok = 1;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                base = 16;
                p += 2;
            }
            if (!*p || is_space(*p))
                ok = 0;
            for (; *p && !is_space(*p); p++) {
                int d = *p >= '0' && *p <= '9' ? *p - '0' :
                        *p >= 'a' && *p <= 'f' ? *p - 'a' + 10 :
                        *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : 99;
                if (d >= base || v > 0xffff)
                    ok = 0;
                else
                    v = v * base + d;
            }
            mode = ok ? v : 0;
            continue;
        }
        p++;
    }
    return mode;
}

static void setup_lfb(struct linux_params *params, const char *cmdline)
{
    int mode = vga_mode(cmdline), i, devfn;
    for (i = 0; i < sizeof(vesa_modes) / sizeof(vesa_modes[0]); i++)
        if (vesa_modes[i].mode == mode)
            break;
    if (i == sizeof(vesa_modes) / sizeof(vesa_modes[0]))
        return;
    if ((dispi_get(VBE_DISPI_INDEX_ID) & 0xfff0) != 0xb0c0)
        return;
    int w = vesa_modes[i].w, h = vesa_modes[i].h, bpp = vesa_modes[i].bpp;
    int line = w * ((bpp + 7) / 8);
    uint32_t mem = dispi_get(VBE_DISPI_INDEX_VIDEO_MEMORY_64K) * 65536u;
    dispi_set(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_GETCAPS);   /* the largest mode */
    int max_w = dispi_get(VBE_DISPI_INDEX_XRES), max_h = dispi_get(VBE_DISPI_INDEX_YRES);
    int max_bpp = dispi_get(VBE_DISPI_INDEX_BPP);
    dispi_set(VBE_DISPI_INDEX_ENABLE, 0);
    if (w > max_w || h > max_h || bpp > max_bpp || (uint32_t) line * h > mem) {
        put_string("vga=: the display can't show that mode\n");
        return;
    }
    /* the VGA on the PCI bus, its frame buffer mapped */
    for (devfn = 0; devfn < 256; devfn += 8)
        if (pci_read(devfn, 0) == 0x11111234)
            break;
    if (devfn == 256)
        return;
    uint32_t base = pci_read(devfn, 0x10) & ~0xfu;
    if (!base) {
        pci_write(devfn, 0x10, LFB_DEFAULT_BASE);
        base = pci_read(devfn, 0x10) & ~0xfu;
    }
    pci_command_set(devfn, 0x0002);   /* memory decoding */
    io_outl(0xcf8, 0x80000000u | devfn << 8 | 0x04);
    if (!base || !(io_inw(0xcfc) & 0x0002))
        return;

    /* first without clearing video memory (text mode's characters and font
       are there), so that text mode can be put back if the mode isn't usable */
    uint8_t vga[VGA_SAVED];
    vga_save(vga);
    dispi_set(VBE_DISPI_INDEX_XRES, w);
    dispi_set(VBE_DISPI_INDEX_YRES, h);
    dispi_set(VBE_DISPI_INDEX_BPP, bpp);
    dispi_set(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM);
    /* the kernel is told of the mode only as the display has it */
    line = dispi_get(VBE_DISPI_INDEX_VIRT_WIDTH) * ((bpp + 7) / 8);
    if (dispi_get(VBE_DISPI_INDEX_XRES) != w || dispi_get(VBE_DISPI_INDEX_YRES) != h ||
        dispi_get(VBE_DISPI_INDEX_BPP) != bpp ||
        (dispi_get(VBE_DISPI_INDEX_ENABLE) & (VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED)) !=
            (VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED) ||
        line < w * ((bpp + 7) / 8) || (uint32_t) line * h > mem) {
        dispi_set(VBE_DISPI_INDEX_ENABLE, 0);
        vga_restore(vga);
        put_string("vga=: the display didn't take that mode\n");
        return;
    }
    /* usable: on again, this time with video memory cleared */
    dispi_set(VBE_DISPI_INDEX_ENABLE, 0);
    dispi_set(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    params->orig_video_isVGA = VIDEO_TYPE_VLFB;
    params->lfb_width = w;
    params->lfb_height = h;
    params->lfb_depth = bpp;
    params->lfb_base = base;
    params->lfb_size = mem >> 16;
    params->lfb_linelength = line;
    params->pages = 1;
    if (bpp == 8) {   /* a palette, through the VGA's 6-bit DAC */
        params->red_size = params->green_size = params->blue_size = 6;
    } else if (bpp == 15) {
        params->red_size = params->green_size = params->blue_size = 5;
        params->red_pos = 10;
        params->green_pos = 5;
    } else if (bpp == 16) {
        params->red_size = params->blue_size = 5;
        params->green_size = 6;
        params->red_pos = 11;
        params->green_pos = 5;
    } else {
        params->red_size = params->green_size = params->blue_size = 8;
        params->red_pos = 16;
        params->green_pos = 8;
    }
}

void setup(int phys_ram_size, int initrd_size, char *cmdline, int kernel_size)
{
    struct linux_params *params = (struct linux_params *) KERNEL_PARAMS_ADDR;
    struct __attribute__((packed)) {
        uint16_t limit;
        void *addr;
    } gdt_data;

    memset(params, 0, sizeof(struct linux_params));
    put_string("Starting Linux\n");
    if (*(uint32_t *) (KERNEL_LOAD_ADDR + 0x202) == 0x53726448 /* "HdrS" */) {
        // The 32-bit (non-real-mode) kernel starts at offset
        // (setup_sects+1)*512 in the kernel file (again, if
        // setup_sects == 0 the real value is 4.) It should be
        // loaded at address 0x10000 for Image/zImage kernels
        // and 0x100000 for bzImage kernels.
        // --- The Linux Kernel documentation
        int setup_sects = *(uint8_t *) (KERNEL_LOAD_ADDR + 0x1f1);
        if (setup_sects == 0)
          setup_sects = 4;
        int off = (setup_sects + 1) * 512;
        memmove((void *) params + 0x1f1, (void *) KERNEL_LOAD_ADDR + 0x1f1,
                0x2d0 - 0x1f1);
        memmove((void *) KERNEL_LOAD_ADDR,
                (void *) (KERNEL_LOAD_ADDR + off),
                kernel_size - off);
    }

    params->mount_root_rdonly = 0;
    params->cmd_line_ptr = (uintptr_t)params->commandline;
    params->alt_mem_k = (phys_ram_size / 1024) - 1024;
    // It seems like linux 7.0+ doesn't support non-e820 system anymore...
    params->e820map_entries = 2;
    params->e820map[0].addr = 0;
    params->e820map[0].size = 640 * 1024;
    params->e820map[0].type = E820_RAM;
    params->e820map[1].addr = 1024 * 1024;
    params->e820map[1].size = params->alt_mem_k * 1024;
    params->e820map[1].type = E820_RAM;

    strcpy((char *)params->commandline, cmdline);

    params->loader_type = 0x01;

    if (initrd_size > 0) {
        params->initrd_start = INITRD_LOAD_ADDR;
        params->initrd_size = initrd_size;
    }

    params->orig_video_mode = 3;
    params->orig_video_cols = 80;
    params->orig_video_lines = 25;
    params->orig_video_ega_bx = 3;
    params->orig_video_isVGA = 1;
    params->orig_video_points = 16;
    setup_lfb(params, cmdline);

#ifndef __amd64__
    params->gdt_table[2] = 0x00cf9a000000ffffLL; /* KERNEL_CS */
    params->gdt_table[3] = 0x00cf92000000ffffLL; /* KERNEL_DS */
#else
    params->gdt_table[2] = 0x00af9a000000ffffLL; /* KERNEL_CS */
    params->gdt_table[3] = 0x00cf92000000ffffLL; /* KERNEL_DS */
    params->gdt_table[4] = 0x0080890000000000LL; /* TS descriptor */
    params->gdt_table[5] = 0x0000000000000000LL; /* TS continued */
#endif

    gdt_data.limit = sizeof(params->gdt_table);
    gdt_data.addr = params->gdt_table;

    /* init gdt */
    asm volatile ("lgdt (%0)" : : "r" (&gdt_data) : "memory");
}
