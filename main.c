#ifdef BUILD_ESP32
#define NOSDL
#else
//#define USEKVM
//#define NOSDL
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "i386.h"
#include "i8259.h"
#include "i8254.h"
#include "ide.h"
#include "vga.h"
#include "i8042.h"
#include "misc.h"
#include "adlib.h"
#include "ne2000.h"
#include "i8257.h"
#include "sb16.h"
#include "pcspk.h"
#include "pci.h"

#include "ini.h"

#ifdef BUILD_ESP32
#include "esp_private/system_internal.h"
static uint32_t get_uticks()
{
	return esp_system_get_time();
}
#else
#include <time.h>
static uint32_t get_uticks()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint32_t) ts.tv_sec * 1000000 +
		(uint32_t) ts.tv_nsec / 1000);
}
#endif

#ifdef USEKVM
#include "kvm.h"
#include <sys/mman.h>
typedef CPUKVM CPU;
#define cpu_raise_irq cpukvm_raise_irq
#define cpu_get_cycle cpukvm_get_cycle
void *bigmalloc(size_t size)
{
	return mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
#else
typedef CPUI386 CPU;
#define cpu_raise_irq cpui386_raise_irq
#define cpu_get_cycle cpui386_get_cycle
#ifdef BUILD_ESP32
void *psmalloc(long size);
void *fbmalloc(long size);
void *bigmalloc(size_t size)
{
	return psmalloc(size);
}
static char *pcram;
static long pcram_off;
static long pcram_len;
void *pcmalloc(long size)
{
	void *ret = pcram + pcram_off;

	size = (size + 31) / 32 * 32;
	if (pcram_off + size > pcram_len) {
		printf("pcram error %ld %ld %ld\n", size, pcram_off, pcram_len);
		abort();
	}
	pcram_off += size;
	return ret;
}
#else
void *bigmalloc(size_t size)
{
	return malloc(size);
}
#endif
#endif

typedef struct {
	CPU *cpu;
	PicState2 *pic;
	PITState *pit;
	U8250 *serial;
	CMOS *cmos;
	IDEIFState *ide, *ide2;
	VGAState *vga;
	char *phys_mem;
	long phys_mem_size;
	char *vga_mem;
	int vga_mem_size;
	int64_t boot_start_time;

	SimpleFBDrawFunc *redraw;
	void *redraw_data;
	void (*poll)(void *);

	KBDState *i8042;
	PS2KbdState *kbd;
	PS2MouseState *mouse;
	AdlibState *adlib;
	NE2000State *ne2000;
	I8257State *isa_dma, *isa_hdma;
	SB16State *sb16;
	PCSpkState *pcspk;

	I440FXState *i440fx;
	PCIBus *pcibus;
	PCIDevice *pci_ide;
	PCIDevice *pci_vga;
	uword pci_vga_ram_addr;

	EMULINK *emulink;

	const char *bios;
	const char *vga_bios;

	u8 port92;
	int shutdown_state;
	int reset_request;

	const char *linuxstart;
	const char *kernel;
	const char *initrd;
	const char *cmdline;
	int enable_serial;
	int full_update;
} PC;

static u8 pc_io_read(void *o, int addr)
{
	PC *pc = o;
	u8 val;

	switch(addr) {
	case 0x20: case 0x21: case 0xa0: case 0xa1:
		val = i8259_ioport_read(pc->pic, addr);
		return val;
	case 0x3f8: case 0x3f9: case 0x3fa: case 0x3fb:
	case 0x3fc: case 0x3fd: case 0x3fe: case 0x3ff:
		val = 0xff;
		if (pc->enable_serial)
			val = u8250_reg_read(pc->serial, addr - 0x3f8);
		return val;
	case 0x2f8: case 0x2f9: case 0x2fa: case 0x2fb:
	case 0x2fc: case 0x2fd: case 0x2fe: case 0x2ff:
	case 0x2e8: case 0x2e9: case 0x2ea: case 0x2eb:
	case 0x2ec: case 0x2ed: case 0x2ee: case 0x2ef:
	case 0x3e8: case 0x3e9: case 0x3ea: case 0x3eb:
	case 0x3ec: case 0x3ed: case 0x3ee: case 0x3ef:
		return 0;
	case 0x42:
		/* read delay for PIT channel 2 */
		/* certain guest code needs it to drive pc speaker properly */
		usleep(0);
		/* fall through */
	case 0x40: case 0x41: case 0x43:
		val = i8254_ioport_read(pc->pit, addr);
		return val;
	case 0x70: case 0x71:
		val = cmos_ioport_read(pc->cmos, addr);
		return val;
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		val = ide_ioport_read(pc->ide, addr - 0x1f0);
		return val;
	case 0x170: case 0x171: case 0x172: case 0x173:
	case 0x174: case 0x175: case 0x176: case 0x177:
		val = ide_ioport_read(pc->ide2, addr - 0x170);
		return val;
	case 0x3f6:
		val = ide_status_read(pc->ide);
		return val;
	case 0x376:
		val = ide_status_read(pc->ide2);
		return val;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de: case 0x3df:
		val = vga_ioport_read(pc->vga, addr);
		return val;
	case 0x92:
		return pc->port92;
	case 0x60:
		val = kbd_read_data(pc->i8042, addr);
		return val;
	case 0x64:
		val = kbd_read_status(pc->i8042, addr);
		return val;
	case 0x61:
		val = pcspk_ioport_read(pc->pcspk);
		return val;
	case 0x220: case 0x221: case 0x222: case 0x223:
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a: case 0x38b:
		return adlib_read(pc->adlib, addr);
	case 0xcfc: case 0xcfd: case 0xcfe: case 0xcff:
		val = i440fx_read_data(pc->i440fx, addr - 0xcfc, 0);
		return val;
	case 0x300: case 0x301: case 0x302: case 0x303:
	case 0x304: case 0x305: case 0x306: case 0x307:
	case 0x308: case 0x309: case 0x30a: case 0x30b:
	case 0x30c: case 0x30d: case 0x30e: case 0x30f:
		val = ne2000_ioport_read(pc->ne2000, addr);
		return val;
	case 0x310:
		val = ne2000_asic_ioport_read(pc->ne2000, addr);
		return val;
	case 0x31f:
		val = ne2000_reset_ioport_read(pc->ne2000, addr);
		return val;
	case 0x00: case 0x01: case 0x02: case 0x03:
	case 0x04: case 0x05: case 0x06: case 0x07:
		val = i8257_read_chan(pc->isa_dma, addr - 0x00, 1);
		return val;
	case 0x08: case 0x09: case 0x0a: case 0x0b:
	case 0x0c: case 0x0d: case 0x0e: case 0x0f:
		val = i8257_read_cont(pc->isa_dma, addr - 0x08, 1);
		return val;
	case 0x81: case 0x82: case 0x83: case 0x87:
		val = i8257_read_page(pc->isa_dma, addr - 0x80);
		return val;
	case 0x481: case 0x482: case 0x483: case 0x487:
		val = i8257_read_pageh(pc->isa_dma, addr - 0x480);
		return val;
	case 0xc0: case 0xc2: case 0xc4: case 0xc6:
	case 0xc8: case 0xca: case 0xcc: case 0xce:
		val = i8257_read_chan(pc->isa_hdma, addr - 0xc0, 1);
		return val;
	case 0xd0: case 0xd2: case 0xd4: case 0xd6:
	case 0xd8: case 0xda: case 0xdc: case 0xde:
		val = i8257_read_cont(pc->isa_hdma, addr - 0xd0, 1);
		return val;
	case 0x89: case 0x8a: case 0x8b: case 0x8f:
		val = i8257_read_page(pc->isa_hdma, addr - 0x88);
		return val;
	case 0x489: case 0x48a: case 0x48b: case 0x48f:
		val = i8257_read_pageh(pc->isa_hdma, addr - 0x488);
		return val;
	case 0x225:
		val = sb16_mixer_read(pc->sb16, addr);
		return val;
	case 0x226: case 0x22a: case 0x22c: case 0x22d: case 0x22e: case 0x22f:
		val = sb16_dsp_read(pc->sb16, addr);
		return val;
	case 0xf1f4:
		val = 0;
		emulink_data_read_string(pc->emulink, &val, 1, 1);
		return val;
	default:
		//fprintf(stderr, "in 0x%x <= 0x%x\n", addr, 0xff);
		return 0xff;
	}
}

static u16 pc_io_read16(void *o, int addr)
{
	PC *pc = o;
	u16 val;

	switch(addr) {
	case 0x1ce: case 0x1cf:
		val = vbe_read(pc->vga, addr - 0x1ce);
		return val;
	case 0x1f0:
		val = ide_data_readw(pc->ide);
		return val;
	case 0x170:
		val = ide_data_readw(pc->ide2);
		return val;
	case 0xcf8:
		val = i440fx_read_addr(pc->i440fx, 0, 1);
		return val;
	case 0xcfc: case 0xcfe:
		val = i440fx_read_data(pc->i440fx, addr - 0xcfc, 1);
		return val;
	case 0x310:
		val = ne2000_asic_ioport_read(pc->ne2000, addr);
		return val;
	case 0x220:
		return adlib_read(pc->adlib, addr);
	default:
		fprintf(stderr, "inw 0x%x <= 0x%x\n", addr, 0xffff);
		return 0xffff;
	}
}

static u32 pc_io_read32(void *o, int addr)
{
	PC *pc = o;
	u32 val;
	switch(addr) {
	case 0x1f0:
		val = ide_data_readl(pc->ide);
		return val;
	case 0x170:
		val = ide_data_readl(pc->ide2);
		return val;
	case 0x3cc:
		return (get_uticks() - pc->boot_start_time) / 1000;
	case 0xcf8:
		val = i440fx_read_addr(pc->i440fx, 0, 2);
		return val;
	case 0xcfc:
		val = i440fx_read_data(pc->i440fx, 0, 2);
		return val;
	case 0xf1f0:
		val = emulink_status_read(pc->emulink);
		return val;
	default:
		fprintf(stderr, "ind 0x%x <= 0x%x\n", addr, 0xffffffff);
	}
	return 0xffffffff;
}

static int pc_io_read_string(void *o, int addr, uint8_t *buf, int size, int count)
{
	PC *pc = o;
	u32 val;

	switch(addr) {
	case 0x1f0:
		return ide_data_read_string(pc->ide, buf, size, count);
	case 0x170:
		return ide_data_read_string(pc->ide2, buf, size, count);
	case 0xf1f4:
		return emulink_data_read_string(pc->emulink, buf, size, count);
	}
	return 0;
}

static void pc_io_write(void *o, int addr, u8 val)
{
	PC *pc = o;
	switch(addr) {
	case 0x80: case 0xed:
		/* used by linux, for io delay */
		return;
	case 0x20: case 0x21: case 0xa0: case 0xa1:
		i8259_ioport_write(pc->pic, addr, val);
		return;
	case 0x3f8: case 0x3f9: case 0x3fa: case 0x3fb:
	case 0x3fc: case 0x3fd: case 0x3fe: case 0x3ff:
		u8250_reg_write(pc->serial, addr - 0x3f8, val);
		return;
	case 0x2f8: case 0x2f9: case 0x2fa: case 0x2fb:
	case 0x2fc: case 0x2fd: case 0x2fe: case 0x2ff:
	case 0x2e8: case 0x2e9: case 0x2ea: case 0x2eb:
	case 0x2ec: case 0x2ed: case 0x2ee: case 0x2ef:
	case 0x3e8: case 0x3e9: case 0x3ea: case 0x3eb:
	case 0x3ec: case 0x3ed: case 0x3ee: case 0x3ef:
		return;
	case 0x40: case 0x41: case 0x42: case 0x43:
		i8254_ioport_write(pc->pit, addr, val);
		return;
	case 0x70: case 0x71:
		cmos_ioport_write(pc->cmos, addr, val);
		return;
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		ide_ioport_write(pc->ide, addr - 0x1f0, val);
		return;
	case 0x170: case 0x171: case 0x172: case 0x173:
	case 0x174: case 0x175: case 0x176: case 0x177:
		ide_ioport_write(pc->ide2, addr - 0x170, val);
		return;
	case 0x3f6:
		ide_cmd_write(pc->ide, val);
		return;
	case 0x376:
		ide_cmd_write(pc->ide2, val);
		return;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de: case 0x3df:
		vga_ioport_write(pc->vga, addr, val);
		return;
	case 0x402:
		putchar(val);
		fflush(stdout);
		return;
	case 0x92:
		pc->port92 = val;
		return;
	case 0x60:
		kbd_write_data(pc->i8042, addr, val);
		return;
	case 0x64:
		kbd_write_command(pc->i8042, addr, val);
		return;
	case 0x61:
		pcspk_ioport_write(pc->pcspk, val);
		return;
	case 0x220: case 0x221: case 0x222: case 0x223:
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a: case 0x38b:
		adlib_write(pc->adlib, addr, val);
		return;
	case 0x8900:
		switch (val) {
		case 'S': if (pc->shutdown_state == 0) pc->shutdown_state = 1; break;
		case 'h': if (pc->shutdown_state == 1) pc->shutdown_state = 2; break;
		case 'u': if (pc->shutdown_state == 2) pc->shutdown_state = 3; break;
		case 't': if (pc->shutdown_state == 3) pc->shutdown_state = 4; break;
		case 'd': if (pc->shutdown_state == 4) pc->shutdown_state = 5; break;
		case 'o': if (pc->shutdown_state == 5) pc->shutdown_state = 6; break;
		case 'w': if (pc->shutdown_state == 6) pc->shutdown_state = 7; break;
		case 'n': if (pc->shutdown_state == 7) pc->shutdown_state = 8; break;
		default : pc->shutdown_state = 0; break;
		}
		return;
	case 0xcfc: case 0xcfd: case 0xcfe: case 0xcff:
		i440fx_write_data(pc->i440fx, addr - 0xcfc, val, 0);
		return;
	case 0x300: case 0x301: case 0x302: case 0x303:
	case 0x304: case 0x305: case 0x306: case 0x307:
	case 0x308: case 0x309: case 0x30a: case 0x30b:
	case 0x30c: case 0x30d: case 0x30e: case 0x30f:
		ne2000_ioport_write(pc->ne2000, addr, val);
		return;
	case 0x310:
		ne2000_asic_ioport_write(pc->ne2000, addr, val);
		return;
	case 0x31f:
		ne2000_reset_ioport_write(pc->ne2000, addr, val);
		return;
	case 0x00: case 0x01: case 0x02: case 0x03:
	case 0x04: case 0x05: case 0x06: case 0x07:
		i8257_write_chan(pc->isa_dma, addr - 0x00, val, 1);
		return;
	case 0x08: case 0x09: case 0x0a: case 0x0b:
	case 0x0c: case 0x0d: case 0x0e: case 0x0f:
		i8257_write_cont(pc->isa_dma, addr - 0x08, val, 1);
		return;
	case 0x81: case 0x82: case 0x83: case 0x87:
		i8257_write_page(pc->isa_dma, addr - 0x80, val);
		return;
	case 0x481: case 0x482: case 0x483: case 0x487:
		i8257_write_pageh(pc->isa_dma, addr - 0x480, val);
		return;
	case 0xc0: case 0xc2: case 0xc4: case 0xc6:
	case 0xc8: case 0xca: case 0xcc: case 0xce:
		i8257_write_chan(pc->isa_hdma, addr - 0xc0, val, 1);
		return;
	case 0xd0: case 0xd2: case 0xd4: case 0xd6:
	case 0xd8: case 0xda: case 0xdc: case 0xde:
		i8257_write_cont(pc->isa_hdma, addr - 0xd0, val, 1);
		return;
	case 0x89: case 0x8a: case 0x8b: case 0x8f:
		i8257_write_page(pc->isa_hdma, addr - 0x88, val);
		return;
	case 0x489: case 0x48a: case 0x48b: case 0x48f:
		i8257_write_pageh(pc->isa_hdma, addr - 0x488, val);
		return;
	case 0x224:
		sb16_mixer_write_indexb(pc->sb16, addr, val);
		return;
	case 0x225:
		sb16_mixer_write_datab(pc->sb16, addr, val);
		return;
	case 0x226: case 0x22c:
		sb16_dsp_write(pc->sb16, addr, val);
		return;
	case 0xf1f4:
		emulink_data_write_string(pc->emulink, &val, 1, 1);
		return;
	default:
		fprintf(stderr, "out 0x%x => 0x%x\n", val, addr);
		return;
	}
}

static void pc_io_write16(void *o, int addr, u16 val)
{
	PC *pc = o;
	switch(addr) {
	case 0x1f0:
		ide_data_writew(pc->ide, val);
		return;
	case 0x170:
		ide_data_writew(pc->ide2, val);
		return;
	case 0x3c0: case 0x3c1: case 0x3c2: case 0x3c3:
	case 0x3c4: case 0x3c5: case 0x3c6: case 0x3c7:
	case 0x3c8: case 0x3c9: case 0x3ca: case 0x3cb:
	case 0x3cc: case 0x3cd: case 0x3ce: case 0x3cf:
	case 0x3d0: case 0x3d1: case 0x3d2: case 0x3d3:
	case 0x3d4: case 0x3d5: case 0x3d6: case 0x3d7:
	case 0x3d8: case 0x3d9: case 0x3da: case 0x3db:
	case 0x3dc: case 0x3dd: case 0x3de:
		vga_ioport_write(pc->vga, addr, val & 0xff);
		vga_ioport_write(pc->vga, addr + 1, (val >> 8) & 0xff);
		return;
	case 0x1ce: case 0x1cf:
		vbe_write(pc->vga, addr - 0x1ce, val);
		return;
	case 0xcfc: case 0xcfe:
		i440fx_write_data(pc->i440fx, addr - 0xcfc, val, 1);
		return;
	case 0x310:
		ne2000_asic_ioport_write(pc->ne2000, addr, val);
		return;
	default:
		fprintf(stderr, "outw 0x%x => 0x%x\n", val, addr);
		return;
	}
}

static void pc_io_write32(void *o, int addr, u32 val)
{
	PC *pc = o;
	switch(addr) {
	case 0x1f0:
		ide_data_writel(pc->ide, val);
		return;
	case 0x170:
		ide_data_writel(pc->ide2, val);
		return;
	case 0xcf8:
		i440fx_write_addr(pc->i440fx, 0, val, 2);
		return;
	case 0xcfc:
		i440fx_write_data(pc->i440fx, 0, val, 2);
		return;
	case 0xf1f0:
		emulink_cmd_write(pc->emulink, val);
		return;
	case 0xf1f4:
		emulink_data_write(pc->emulink, val);
		return;
	default:
		fprintf(stderr, "outd 0x%x => 0x%x\n", val, addr);
		return;
	}
}

static int pc_io_write_string(void *o, int addr, uint8_t *buf, int size, int count)
{
	PC *pc = o;
	switch(addr) {
	case 0x1f0:
		return ide_data_write_string(pc->ide, buf, size, count);
	case 0x170:
		return ide_data_write_string(pc->ide2, buf, size, count);
	case 0xf1f4:
		return emulink_data_write_string(pc->emulink, buf, size, count);
	}
	return 0;
}

static void load_bios_and_reset(PC *pc);
void pc_vga_step(void *o)
{
	PC *pc = o;
	int refresh = vga_step(pc->vga);
	if (refresh) {
		vga_refresh(pc->vga, pc->redraw, pc->redraw_data, 0);
	}
}

void pc_step(PC *pc)
{
#ifndef USEKVM
	if (pc->reset_request) {
		pc->reset_request = 0;
		load_bios_and_reset(pc);
	}
#endif
#ifndef BUILD_ESP32
	int refresh = vga_step(pc->vga);
#endif
	i8254_update_irq(pc->pit);
	cmos_update_irq(pc->cmos);
	if (pc->enable_serial)
		u8250_update(pc->serial);
	kbd_step(pc->i8042);
	ne2000_step(pc->ne2000);
	i8257_dma_run(pc->isa_dma);
	i8257_dma_run(pc->isa_hdma);
#ifndef BUILD_ESP32
	pc->poll(pc->redraw_data);
	if (refresh) {
		vga_refresh(pc->vga, pc->redraw, pc->redraw_data,
			    pc->full_update != 0);
		if (pc->full_update == 2)
			pc->full_update = 0;
	}
#endif
#ifdef USEKVM
	cpukvm_step(pc->cpu, 4096);
#else
#ifdef BUILD_ESP32
	for (int i = 0; i < 4; i++) {
		cpui386_step(pc->cpu, 128);
		kbd_step(pc->i8042);
	}
#else
	cpui386_step(pc->cpu, 10240);
#endif
#endif
}

static void raise_irq(void *o, PicState2 *s)
{
	cpu_raise_irq(o);
}

static int read_irq(void *o)
{
	PicState2 *s = o;
	return i8259_read_irq(s);
}

static void set_irq(void *o, int irq, int level)
{
	PicState2 *s = o;
	return i8259_set_irq(s, irq, level);
}

static void set_pci_vga_bar(void *opaque, int bar_num, uint32_t addr, bool enabled)
{
	PC *pc = opaque;
	if (enabled)
		pc->pci_vga_ram_addr = addr;
	else
		pc->pci_vga_ram_addr = -1;
#ifdef USEKVM
	if (enabled)
		cpukvm_register_mem(pc->cpu, 2, addr, pc->vga_mem_size,
				    pc->vga_mem);
	else
		cpukvm_register_mem(pc->cpu, 2, addr, 0,
				    NULL);
#endif
}

static u8 iomem_read8(void *iomem, uword addr)
{
	PC *pc = iomem;
	uword vga_addr2 = pc->pci_vga_ram_addr;
	if (addr >= vga_addr2) {
		addr -= vga_addr2;
		if (addr < pc->vga_mem_size)
			return pc->vga_mem[addr];
		else
			return 0;
	}
	return vga_mem_read(pc->vga, addr - 0xa0000);
}

static void iomem_write8(void *iomem, uword addr, u8 val)
{
	PC *pc = iomem;
	uword vga_addr2 = pc->pci_vga_ram_addr;
	if (addr >= vga_addr2) {
		addr -= vga_addr2;
		if (addr < pc->vga_mem_size)
			pc->vga_mem[addr] = val;
		return;
	}
	vga_mem_write(pc->vga, addr - 0xa0000, val);
}

static u16 iomem_read16(void *iomem, uword addr)
{
	return iomem_read8(iomem, addr) |
		((u16) iomem_read8(iomem, addr + 1) << 8);
}

static void iomem_write16(void *iomem, uword addr, u16 val)
{
	PC *pc = iomem;
	// fast path for vga ram
	uword vga_addr2 = pc->pci_vga_ram_addr;
	if (addr >= vga_addr2) {
		addr -= vga_addr2;
		if (addr + 1 < pc->vga_mem_size)
			*(uint16_t *)&(pc->vga_mem[addr]) = val;
		return;
	}
	vga_mem_write16(pc->vga, addr - 0xa0000, val);
}

static u32 iomem_read32(void *iomem, uword addr)
{
	return iomem_read16(iomem, addr) |
		((u32) iomem_read16(iomem, addr + 2) << 16);
}

static void iomem_write32(void *iomem, uword addr, u32 val)
{
	PC *pc = iomem;
	// fast path for vga ram
	uword vga_addr2 = pc->pci_vga_ram_addr;
	if (addr >= vga_addr2) {
		uword vga_addr2 = pc->pci_vga_ram_addr;
		addr -= vga_addr2;
		if (addr + 3 < pc->vga_mem_size)
			*(uint32_t *)&(pc->vga_mem[addr]) = val;
		return;
	}
	vga_mem_write32(pc->vga, addr - 0xa0000, val);
}

static bool iomem_write_string(void *iomem, uword addr, uint8_t *buf, int len)
{
	PC *pc = iomem;
	// fast path for vga ram
	uword vga_addr2 = pc->pci_vga_ram_addr;
	if (addr >= vga_addr2) {
		uword vga_addr2 = pc->pci_vga_ram_addr;
		addr -= vga_addr2;
		if (addr + len < pc->vga_mem_size) {
			memcpy(pc->vga_mem + addr, buf, len);
			return true;
		}
		return false;
	}
	return vga_mem_write_string(pc->vga, addr - 0xa0000, buf, len);
}

static void pc_reset_request(void *p)
{
	PC *pc = p;
	pc->reset_request = 1;
}

struct pcconfig {
	const char *linuxstart;
	const char *kernel;
	const char *initrd;
	const char *cmdline;
	const char *bios;
	const char *vga_bios;
	long mem_size;
	long vga_mem_size;
	const char *disks[4];
	int iscd[4];
	const char *fdd[2];
	int fill_cmos;
	int width;
	int height;
	int cpu_gen;
	int fpu;
	int enable_serial;
};

PC *pc_new(SimpleFBDrawFunc *redraw, void (*poll)(void *), void *redraw_data,
	   u8 *fb, struct pcconfig *conf)
{
	PC *pc = malloc(sizeof(PC));
	char *mem = bigmalloc(conf->mem_size);
	CPU_CB *cb = NULL;
	memset(mem, 0, conf->mem_size);
#ifdef BUILD_ESP32
	pcram = mem + 0xa0000;
	pcram_len = 0xc0000 - 0xa0000;
#endif
#ifdef USEKVM
	pc->cpu = cpukvm_new(mem, conf->mem_size, &cb);
#else
	pc->cpu = cpui386_new(conf->cpu_gen, mem, conf->mem_size, &cb);
	if (conf->fpu)
		cpui386_enable_fpu(pc->cpu);
#endif
	pc->bios = conf->bios;
	pc->vga_bios = conf->vga_bios;
	pc->linuxstart = conf->linuxstart;
	pc->kernel = conf->kernel;
	pc->initrd = conf->initrd;
	pc->cmdline = conf->cmdline;
	pc->enable_serial = conf->enable_serial;
	if (pc->enable_serial)
		CaptureKeyboardInput();
	pc->full_update = 0;

	pc->pic = i8259_init(raise_irq, pc->cpu);
	cb->pic = pc->pic;
	cb->pic_read_irq = read_irq;

	pc->pit = i8254_init(0, pc->pic, set_irq);
	pc->serial = u8250_init(4, pc->pic, set_irq);
	pc->cmos = cmos_init(conf->mem_size, 8, pc->pic, set_irq);
	pc->ide = ide_allocate(14, pc->pic, set_irq);
	pc->ide2 = ide_allocate(15, pc->pic, set_irq);
	const char **disks = conf->disks;
	for (int i = 0; i < 4; i++) {
		if (!disks[i] || disks[i][0] == 0)
			continue;
		int ret;
		if (i < 2) {
			if (conf->iscd[i])
				ret = ide_attach_cd(pc->ide, i, disks[i]);
			else
				ret = ide_attach(pc->ide, i, disks[i]);
			assert(ret == 0);
		} else {
			if (conf->iscd[i])
				ret = ide_attach_cd(pc->ide2, i - 2, disks[i]);
			else
				ret = ide_attach(pc->ide2, i - 2, disks[i]);
			assert(ret == 0);
		}
	}

	if (conf->fill_cmos)
		ide_fill_cmos(pc->ide, pc->cmos, cmos_set);

	int piix3_devfn;
	pc->i440fx = i440fx_init(&pc->pcibus, &piix3_devfn);
	pc->pci_ide = piix3_ide_init(pc->pcibus, piix3_devfn + 1);

	pc->phys_mem = mem;
	pc->phys_mem_size = conf->mem_size;

	cb->io = pc;
	cb->io_read8 = pc_io_read;
	cb->io_write8 = pc_io_write;
	cb->io_read16 = pc_io_read16;
	cb->io_write16 = pc_io_write16;
	cb->io_read32 = pc_io_read32;
	cb->io_write32 = pc_io_write32;
	cb->io_read_string = pc_io_read_string;
	cb->io_write_string = pc_io_write_string;

	pc->boot_start_time = 0;

	pc->vga_mem_size = conf->vga_mem_size;
	pc->vga_mem = bigmalloc(pc->vga_mem_size);
	memset(pc->vga_mem, 0, pc->vga_mem_size);
	pc->vga = vga_init(pc->vga_mem, pc->vga_mem_size,
			   fb, conf->width, conf->height);
	pc->pci_vga = vga_pci_init(pc->vga, pc->pcibus, pc, set_pci_vga_bar);
	pc->pci_vga_ram_addr = -1;

	pc->emulink = emulink_init();
	const char **fdd = conf->fdd;
	for (int i = 0; i < 2; i++) {
		if (!fdd[i] || fdd[i][0] == 0)
			continue;
		int ret;
		ret = emulink_attach_floppy(pc->emulink, i, fdd[i]);
		assert(ret == 0);
	}

	cb->iomem = pc;
	cb->iomem_read8 = iomem_read8;
	cb->iomem_write8 = iomem_write8;
	cb->iomem_read16 = iomem_read16;
	cb->iomem_write16 = iomem_write16;
	cb->iomem_read32 = iomem_read32;
	cb->iomem_write32 = iomem_write32;
	cb->iomem_write_string = iomem_write_string;

	pc->redraw = redraw;
	pc->redraw_data = redraw_data;
	pc->poll = poll;

	pc->i8042 = i8042_init(&(pc->kbd), &(pc->mouse),
			       1, 12, pc->pic, set_irq,
			       pc, pc_reset_request);
	pc->adlib = adlib_new();
	pc->ne2000 = isa_ne2000_init(0x300, 9, pc->pic, set_irq);
	pc->isa_dma = i8257_new(pc->phys_mem, pc->phys_mem_size,
				0x00, 0x80, 0x480, 0);
	pc->isa_hdma = i8257_new(pc->phys_mem, pc->phys_mem_size,
				 0xc0, 0x88, 0x488, 1);
	pc->sb16 = sb16_new(0x220, 5,
			    pc->isa_dma, pc->isa_hdma,
			    pc->pic, set_irq);
	pc->pcspk = pcspk_init(pc->pit);
	pc->port92 = 0x2;
	pc->shutdown_state = 0;
	pc->reset_request = 0;
	return pc;
}

#ifdef BUILD_ESP32
#define MIXER_BUF_LEN 128
#else
#define MIXER_BUF_LEN 2048
#endif
void mixer_callback (void *opaque, uint8_t *stream, int free)
{
	uint8_t tmpbuf[MIXER_BUF_LEN];
	PC *pc = opaque;
	assert(free / 2 <= MIXER_BUF_LEN);
	memset(tmpbuf, 0, MIXER_BUF_LEN);
	adlib_callback(pc->adlib, tmpbuf, free / 2); // s16, mono
	sb16_audio_callback(pc->sb16, stream, free); // s16, stereo

	int16_t *d2 = (int16_t *) stream;
	int16_t *d1 = (int16_t *) tmpbuf;
	for (int i = 0; i < free / 2; i++) {
		int res = d2[i] + d1[i / 2];
		if (res > 32767) res = 32767;
		if (res < -32768) res = -32768;
		d2[i] = res;
	}

	if (pcspk_get_active_out(pc->pcspk)) {
		memset(tmpbuf, 0x80, MIXER_BUF_LEN / 2);
		pcspk_callback(pc->pcspk, tmpbuf, free / 4); // u8, mono
		for (int i = 0; i < free / 2; i++) {
			int res = d2[i];
			res += ((int) tmpbuf[i / 2] - 0x80) << 5;
			if (res > 32767) res = 32767;
			if (res < -32768) res = -32768;
			d2[i] = res;
		}
	}
}

#ifdef BUILD_ESP32
#include "esp_partition.h"
static int load(PC *pc, const char *file, uword addr)
{
	char *xfile;
	int len;
	if (strcmp(file, "vmlinux.bin") == 0) {
		xfile = "vmlinux";
		len = 2 * 1024 * 1024;
	} else if (strcmp(file, "linuxstart.bin") == 0) {
		xfile = "linuxstart";
		len = 16 * 1024;
	} else if (strcmp(file, "root.bin") == 0) {
		xfile = "rootbin";
		len = 2 * 1024 * 1024;
	} else if (strcmp(file, "bios.bin") == 0) {
		xfile = "bios";
		len = 128 * 1024;
	} else if (strcmp(file, "vgabios.bin") == 0) {
		xfile = "vgabios";
		len = 64 * 1024;
	} else {
		assert(false);
	}
	const esp_partition_t *part =
		esp_partition_find_first(ESP_PARTITION_TYPE_ANY,
					 ESP_PARTITION_SUBTYPE_ANY,
					 xfile);
	fprintf(stderr, "%s len %d\n", file, len);
	esp_partition_read(part, 0, pc->phys_mem + addr, len);
	return len;
}
#else
static int load(PC *pc, const char *file, uword addr)
{
	FILE *fp = fopen(file, "r");
	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	fprintf(stderr, "%s len %d\n", file, len);
	rewind(fp);
	fread(pc->phys_mem + addr, 1, len, fp);
	fclose(fp);
	return len;
}
#endif

#ifndef NOSDL
#include "SDL.h"
#include "osd/osd.h"
typedef struct {
	int width, height;
	SDL_Surface *screen;
	PC *pc;
	OSD *osd;
	bool osd_enabled;
} Console;

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	s->osd = osd_init();
	s->osd_enabled = false;
#ifdef SWAPXY
	s->width = height;
	s->height = width;
#else
	s->width = width;
	s->height = height;
#endif
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
	s->screen = SDL_SetVideoMode(s->width, s->height, BPP, 0);
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY,
			    SDL_DEFAULT_REPEAT_INTERVAL);
	SDL_WM_SetCaption("tiny386 - use ctrl + ] to grab/ungrab", NULL);
	return s;
}

static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	if (s->osd_enabled)
		osd_render(s->osd, s->screen->pixels,
			   s->screen->w, s->screen->h, s->screen->pitch);
	SDL_Flip(s->screen);
	SDL_PumpEvents();
}

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
	int keycode;
	keycode = ev->keysym.scancode;
	if (keycode == 0) {
		int sym = ev->keysym.sym;
		switch (sym) {
		case SDLK_UP: return 0x67;
		case SDLK_DOWN: return 0x6c;
		case SDLK_LEFT: return 0x69;
		case SDLK_RIGHT: return 0x6a;
		case SDLK_HOME: return 0x66;
		case SDLK_END: return 0x6b;
		case SDLK_PAGEUP: return 0x68;
		case SDLK_PAGEDOWN: return 0x6d;
		case SDLK_INSERT: return 0x6e;
		case SDLK_DELETE: return 0x6f;
		case SDLK_KP_DIVIDE: return 0x62;
		case SDLK_KP_ENTER: return 0x60;
		case SDLK_RCTRL: return 0x61;
		case SDLK_PAUSE: return 0x77;
		case SDLK_PRINT: return 0x63;
		case SDLK_RALT: return 0x64;
		default: printf("unknown %x %d\n", sym, sym); return 0;
		}
	}
	if (keycode < 9) {
		keycode = 0;
	} else if (keycode < 127 + 8) {
		keycode -= 8;
	} else {
		keycode = 0;
	}
	return keycode;
}

/* release all pressed keys */
#define KEYCODE_MAX 127
static uint8_t key_pressed[KEYCODE_MAX + 1];

static void sdl_reset_keys(PC *pc)
{
	int i;
	for(i = 1; i <= KEYCODE_MAX; i++) {
		if (key_pressed[i]) {
			ps2_put_keycode(pc->kbd, 0, i);
			key_pressed[i] = 0;
		}
	}
}

static void sdl_handle_key_event(const SDL_KeyboardEvent *ev, PC *pc)
{
	int keycode, keypress;

	keycode = sdl_get_keycode(ev);
	if (keycode) {
#if SDL_PATCHLEVEL < 50 /* not sdl12-compat */
		if (keycode == 0x3a || keycode ==0x45) {
			/* SDL does not generate key up for numlock & caps lock */
			ps2_put_keycode(pc->kbd, 1, keycode);
			ps2_put_keycode(pc->kbd, 0, keycode);
		} else
#endif
		{
			keypress = (ev->type == SDL_KEYDOWN);
			if (keycode <= KEYCODE_MAX)
				key_pressed[keycode] = keypress;
			ps2_put_keycode(pc->kbd, keypress, keycode);
		}
	} else if (ev->type == SDL_KEYUP) {
		/* workaround to reset the keyboard state (used when changing
		   desktop with ctrl-alt-x on Linux) */
		sdl_reset_keys(pc);
	}
}

static void sdl_send_mouse_event(PC *pc, int x1, int y1,
                                 int dz, int state, bool is_absolute)
{
	int buttons, x, y;

	buttons = 0;
	if (state & SDL_BUTTON(SDL_BUTTON_LEFT))
		buttons |= (1 << 0);
	if (state & SDL_BUTTON(SDL_BUTTON_RIGHT))
		buttons |= (1 << 1);
	if (state & SDL_BUTTON(SDL_BUTTON_MIDDLE))
		buttons |= (1 << 2);
	if (is_absolute) {
		x = 0;//(x1 * 32768) / screen_width;
		y = 0;//(y1 * 32768) / screen_height;
	} else {
		x = x1;
		y = y1;
	}
	ps2_mouse_event(pc->mouse, x, y, dz, buttons);
}

static void sdl_handle_mouse_motion_event(const SDL_Event *ev, PC *pc)
{
	bool is_absolute = 0; //vm_mouse_is_absolute(m);
	int x, y;
	if (is_absolute) {
		x = ev->motion.x;
		y = ev->motion.y;
	} else {
		x = ev->motion.xrel;
		y = ev->motion.yrel;
	}
	sdl_send_mouse_event(pc, x, y, 0, ev->motion.state, is_absolute);
}

static void sdl_handle_mouse_button_event(const SDL_Event *ev, PC *pc)
{
	bool is_absolute = 0; //vm_mouse_is_absolute(m);
	int state, dz;

	dz = 0;
	if (ev->type == SDL_MOUSEBUTTONDOWN) {
		if (ev->button.button == SDL_BUTTON_WHEELUP) {
			dz = -1;
		} else if (ev->button.button == SDL_BUTTON_WHEELDOWN) {
			dz = 1;
		}
	}

	state = SDL_GetMouseState(NULL, NULL);
	/* just in case */
	if (ev->type == SDL_MOUSEBUTTONDOWN)
		state |= SDL_BUTTON(ev->button.button);
	else
		state &= ~SDL_BUTTON(ev->button.button);

	if (is_absolute) {
		sdl_send_mouse_event(pc, ev->button.x, ev->button.y,
				     dz, state, is_absolute);
	} else {
		sdl_send_mouse_event(pc, 0, 0, dz, state, is_absolute);
	}
}

static void poll(void *opaque)
{
	Console *s = opaque;
	SDL_Event ev;
	int keycode;

	while (SDL_PollEvent(&ev)) {
		switch (ev.type) {
		case SDL_KEYDOWN:
			keycode = sdl_get_keycode(&(ev.key));
			if (keycode == 0x1a && key_pressed[0x1d]) {
				s->osd_enabled = !s->osd_enabled;
				osd_attach_emulink(s->osd, s->pc->emulink);
				s->pc->full_update = s->osd_enabled ? 1 : 2;
				break;
			}
			if (keycode == 0x1b && key_pressed[0x1d]) {
				static int en;
				en ^= 1;
				SDL_ShowCursor(en ? SDL_DISABLE : SDL_ENABLE);
				SDL_WM_GrabInput(en ? SDL_GRAB_ON : SDL_GRAB_OFF);
				break;
			}
			/* fall through */
		case SDL_KEYUP:
			if (s->osd_enabled)
				osd_handle_key(s->osd, sdl_get_keycode(&(ev.key)),
					       ev.type == SDL_KEYDOWN);
			else
				sdl_handle_key_event(&(ev.key), s->pc);
			break;
		case SDL_MOUSEMOTION:
			if (s->osd_enabled)
				osd_handle_mouse_motion(s->osd,
							ev.motion.x, ev.motion.y);
			else
				sdl_handle_mouse_motion_event(&ev, s->pc);
			break;
		case SDL_MOUSEBUTTONDOWN:
		case SDL_MOUSEBUTTONUP:
			if (s->osd_enabled)
				osd_handle_mouse_button(
					s->osd,
					ev.button.x, ev.button.y,
					ev.type == SDL_MOUSEBUTTONDOWN,
					1 /* XXX */);
			else
				sdl_handle_mouse_button_event(&ev, s->pc);
			break;
		case SDL_QUIT:
			exit(0);
		}
	}
}

void console_set_audio(Console *console)
{
	SDL_AudioSpec audio_spec = {0};
	audio_spec.freq = 44100;
	audio_spec.format = AUDIO_S16SYS;
	audio_spec.channels = 2;
	audio_spec.samples = 512;
	audio_spec.callback = mixer_callback;
	audio_spec.userdata = console->pc;
	SDL_OpenAudio(&audio_spec, 0);
	SDL_PauseAudio(0);
}

u8 *console_get_fb(Console *console)
{
	return console->screen->pixels;
}
#else
typedef struct {
	PC *pc;
#ifdef BUILD_ESP32
	u8 *fb1;
#endif
	u8 *fb;
} Console;

#define NN 32
Console *console_init(int width, int height)
{
	Console *c = malloc(sizeof(Console));
#ifdef BUILD_ESP32
	c->fb1 = fbmalloc(480 * 320 / NN * 2);
	c->fb = bigmalloc(480 * 320 * 2);
#else
	c->fb = bigmalloc(width * height * 4);
#endif
	return c;
}

#ifdef BUILD_ESP32
extern void *thepanel;
#include "esp_lcd_axs15231b.h"
static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	if (thepanel) {
		for (int i = 0; i < NN; i++) {
			uint16_t *src = s->fb;
			src += 480 * 320 / NN * i;
			memcpy(s->fb1, src, 480 * 320 / NN * 2);
			ESP_ERROR_CHECK(
				esp_lcd_panel_draw_bitmap(
					thepanel,
					0, 480 / NN * i,
					320, 480 / NN * (i + 1),
					s->fb1));
			vga_step(s->pc->vga);
			usleep(900);
		}
	}
}
#else
static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
}
#endif

static void poll(void *opaque)
{
}

void console_set_audio(Console *console)
{
}

u8 *console_get_fb(Console *console)
{
	return console->fb;
}
#endif

static void load_bios_and_reset(PC *pc)
{
	if (pc->bios && pc->bios[0])
		load(pc, pc->bios, 0xe0000);
	if (pc->vga_bios && pc->vga_bios[0])
		load(pc, pc->vga_bios, 0xc0000);
#ifndef USEKVM
	if (pc->kernel && pc->kernel[0]) {
		int start_addr = 0x10000;
		int cmdline_addr = 0xf800;
		int kernel_size = load(pc, pc->kernel, 0x00100000);
		int initrd_size = 0;
		if (pc->initrd && pc->initrd[0])
			initrd_size = load(pc, pc->initrd, 0x00400000);
		if (pc->cmdline && pc->cmdline[0])
			strcpy(pc->phys_mem + cmdline_addr, pc->cmdline);
		else
			strcpy(pc->phys_mem + cmdline_addr, "");

		load(pc, pc->linuxstart, start_addr);
		cpui386_reset_pm(pc->cpu, 0x10000);
		cpui386_set_gpr(pc->cpu, 0, pc->phys_mem_size);
		cpui386_set_gpr(pc->cpu, 3, initrd_size);
		cpui386_set_gpr(pc->cpu, 1, cmdline_addr);
		cpui386_set_gpr(pc->cpu, 2, kernel_size);
	} else {
		cpui386_reset(pc->cpu);
	}
#endif
}

static long parse_mem_size(const char *value)
{
	int len = strlen(value);
	long a = atol(value);
	if (len) {
		switch (value[len - 1]) {
		case 'G': a *= 1024 * 1024 * 1024; break;
		case 'M': a *= 1024 * 1024; break;
		case 'K': a *= 1024; break;
		}
	}
	return a;
}
static int parse_conf_ini(void* user, const char* section,
			  const char* name, const char* value)
{
	struct pcconfig *conf = user;
#define SEC(a) (strcmp(section, a) == 0)
#define NAME(a) (strcmp(name, a) == 0)
	if (SEC("pc")) {
		if (NAME("bios")) {
			conf->bios = strdup(value);
		} else if (NAME("vga_bios")) {
			conf->vga_bios = strdup(value);
		} else if (NAME("mem_size")) {
			conf->mem_size = parse_mem_size(value);
		} else if (NAME("vga_mem_size")) {
			conf->vga_mem_size = parse_mem_size(value);
		} else if (NAME("hda")) {
			conf->disks[0] = strdup(value);
			conf->iscd[0] = 0;
		} else if (NAME("hdb")) {
			conf->disks[1] = strdup(value);
			conf->iscd[1] = 0;
		} else if (NAME("hdc")) {
			conf->disks[2] = strdup(value);
			conf->iscd[2] = 0;
		} else if (NAME("hdd")) {
			conf->disks[3] = strdup(value);
			conf->iscd[3] = 0;
		} else if (NAME("cda")) {
			conf->disks[0] = strdup(value);
			conf->iscd[0] = 1;
		} else if (NAME("cdb")) {
			conf->disks[1] = strdup(value);
			conf->iscd[1] = 1;
		} else if (NAME("cdc")) {
			conf->disks[2] = strdup(value);
			conf->iscd[2] = 1;
		} else if (NAME("cdd")) {
			conf->disks[3] = strdup(value);
			conf->iscd[3] = 1;
		} else if (NAME("fda")) {
			conf->fdd[0] = strdup(value);
		} else if (NAME("fdb")) {
			conf->fdd[1] = strdup(value);
		} else if (NAME("fill_cmos")) {
			conf->fill_cmos = atoi(value);
		} else if (NAME("linuxstart")) {
			conf->linuxstart = strdup(value);
		} else if (NAME("kernel")) {
			conf->kernel = strdup(value);
		} else if (NAME("initrd")) {
			conf->initrd = strdup(value);
		} else if (NAME("cmdline")) {
			conf->cmdline = strdup(value);
		} else if (NAME("enable_serial")) {
			conf->enable_serial = atoi(value);
		}
	} else if (SEC("display")) {
		if (NAME("width")) {
			conf->width = atoi(value);
		} else if (NAME("height")) {
			conf->height = atoi(value);
		}
	} else if (SEC("cpu")) {
		if (NAME("gen")) {
			conf->cpu_gen = atoi(value);
		} else if (NAME("fpu")) {
			conf->fpu = atoi(value);
		}
	}
#undef SEC
#undef NAME
	return 1;
}

#ifdef BUILD_ESP32
extern void *thepc;
extern void *thekbd;
extern void *themouse;
int main(int argc, char *argv[])
{
	struct pcconfig conf;
	memset(&conf, 0, sizeof(conf));
	conf.linuxstart = "linuxstart.bin";
	conf.enable_serial = 0;
	conf.fill_cmos = 1;
	conf.disks[0] = argv[1];
	if (argc >= 3)
		conf.disks[1] = argv[2];
	conf.bios = "bios.bin";
	conf.vga_bios = "vgabios.bin";
	conf.mem_size = 7 * 1024 * 1024 + 460 * 1024 - 28 * 1024 - 52 * 1024;
	conf.vga_mem_size = 256 * 1024;
	conf.width = 480;
	conf.height = 320;
	conf.cpu_gen = 4;
	conf.fpu = 0;

	Console *console = console_init(conf.width, conf.height);
	u8 *fb = console_get_fb(console);
	PC *pc = pc_new(redraw, poll, console, fb, &conf);
	console->pc = pc;
	console_set_audio(console);
	thepc = pc;
	thekbd = pc->kbd;
	themouse = pc->mouse;

	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8;) {
		pc_step(pc);
	}
	return 0;
}
#else
int main(int argc, char *argv[])
{
	struct pcconfig conf;
	memset(&conf, 0, sizeof(conf));
	conf.linuxstart = "linuxstart.bin";
	conf.bios = "bios.bin";
	conf.vga_bios = "vgabios.bin";
	conf.mem_size = 8 * 1024 * 1024;
	conf.vga_mem_size = 256 * 1024;
	conf.width = 720;
	conf.height = 480;
	conf.cpu_gen = 4;
	conf.fpu = 0;

	if (argc != 2)
		return 1;

	int err = ini_parse(argv[1], parse_conf_ini, &conf);
	if (err) {
		printf("error %d\n", err);
		return err;
	}

	Console *console = console_init(conf.width, conf.height);
	u8 *fb = console_get_fb(console);
	PC *pc = pc_new(redraw, poll, console, fb, &conf);
	console->pc = pc;
	console_set_audio(console);

	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8;) {
		pc_step(pc);
	}
	return 0;
}
#endif
