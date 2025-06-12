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
void *bigmalloc(size_t size)
{
	return mmap(NULL, conf->mem_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
#else
typedef CPUI386 CPU;
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

	I440FXState *i440fx;
	PCIBus *pcibus;
	PCIDevice *pci_ide;
	PCIDevice *pci_vga;
	uword pci_vga_ram_addr;

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
} PC;

u8 pc_io_read(void *o, int addr)
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
	case 0x40: case 0x41: case 0x42: case 0x43:
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
		return 0xff;
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a:
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
	default:
		fprintf(stderr, "in 0x%x <= 0x%x\n", addr, 0xff);
		return 0xff;
	}
}

u16 pc_io_read16(void *o, int addr)
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
	default:
		fprintf(stderr, "inw 0x%x <= 0x%x\n", addr, 0xffff);
		return 0xffff;
	}
}

u32 pc_io_read32(void *o, int addr)
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
	default:
		fprintf(stderr, "ind 0x%x <= 0x%x\n", addr, 0xffffffff);
	}
	return 0xffffffff;
}

void pc_io_write(void *o, int addr, u8 val)
{
	PC *pc = o;
	switch(addr) {
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
	case 0x80:
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
		return;
	case 0x228: case 0x229:
	case 0x388: case 0x389: case 0x38a:
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
	default:
		fprintf(stderr, "out 0x%x => 0x%x\n", val, addr);
		return;
	}
}

void pc_io_write16(void *o, int addr, u16 val)
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

void pc_io_write32(void *o, int addr, u32 val)
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
	default:
		fprintf(stderr, "outd 0x%x => 0x%x\n", val, addr);
		return;
	}
}


static void load_bios_and_reset(PC *pc);
void pc_vga_step(void *o)
{
	PC *pc = o;
	int refresh = vga_step(pc->vga);
	if (refresh) {
		vga_refresh(pc->vga, pc->redraw, pc->redraw_data);
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
	pc->poll(pc->redraw_data);
#ifndef BUILD_ESP32
	if (refresh) {
		vga_refresh(pc->vga, pc->redraw, pc->redraw_data);
	}
#endif
#ifdef USEKVM
	cpukvm_step(pc->cpu, 4096);
#else
#ifdef BUILD_ESP32
	cpui386_step(pc->cpu, 192);
#else
	cpui386_step(pc->cpu, 1024);
#endif
#endif
}

static void raise_irq(void *o, PicState2 *s)
{
	CPU *cpu = o;
	cpu->intr = true;
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
//	iomem_write8(iomem, addr, val);
//	iomem_write8(iomem, addr + 1, val >> 8);
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
//	iomem_write16(iomem, addr, val);
//	iomem_write16(iomem, addr + 2, val >> 16);
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
	memset(mem, 0, conf->mem_size);
#ifdef BUILD_ESP32
	pcram = mem + 0xa0000;
	pcram_len = 0xc0000 - 0xa0000;
#endif
#ifdef USEKVM
	pc->cpu = cpukvm_new(mem, conf->mem_size);
#else
	pc->cpu = cpui386_new(conf->cpu_gen, mem, conf->mem_size);
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

	pc->pic = i8259_init(raise_irq, pc->cpu);
	pc->cpu->pic = pc->pic;
	pc->cpu->pic_read_irq = read_irq;

	pc->pit = i8254_init(0, pc->pic, set_irq);
	pc->serial = u8250_init(4, pc->pic, set_irq);
	pc->cmos = cmos_init(conf->mem_size, 8, pc->pic, set_irq);
	pc->ide = ide_allocate(14, pc->pic, set_irq);
	pc->ide2 = ide_allocate(15, pc->pic, set_irq);
	const char **disks = conf->disks;
	for (int i = 0; i < 4; i++) {
		if (!disks[i] || disks[i][0] == 0)
			continue;
		if (i < 2) {
			int ret = ide_attach(pc->ide, i, disks[i]);
			assert(ret == 0);
		} else {
			int ret = ide_attach(pc->ide2, i - 2, disks[i]);
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

	pc->cpu->io = pc;
	pc->cpu->io_read8 = pc_io_read;
	pc->cpu->io_write8 = pc_io_write;
	pc->cpu->io_read16 = pc_io_read16;
	pc->cpu->io_write16 = pc_io_write16;
	pc->cpu->io_read32 = pc_io_read32;
	pc->cpu->io_write32 = pc_io_write32;

	pc->boot_start_time = 0;

	pc->vga_mem_size = conf->vga_mem_size;
	pc->vga_mem = bigmalloc(pc->vga_mem_size);
	memset(pc->vga_mem, 0, pc->vga_mem_size);
	pc->vga = vga_init(pc->vga_mem, pc->vga_mem_size,
			   fb, conf->width, conf->height);
	pc->pci_vga = vga_pci_init(pc->vga, pc->pcibus, pc, set_pci_vga_bar);
	pc->pci_vga_ram_addr = -1;

	pc->cpu->iomem = pc;
	pc->cpu->iomem_read8 = iomem_read8;
	pc->cpu->iomem_write8 = iomem_write8;
	pc->cpu->iomem_read16 = iomem_read16;
	pc->cpu->iomem_write16 = iomem_write16;
	pc->cpu->iomem_read32 = iomem_read32;
	pc->cpu->iomem_write32 = iomem_write32;

	pc->redraw = redraw;
	pc->redraw_data = redraw_data;
	pc->poll = poll;

	pc->i8042 = i8042_init(&(pc->kbd), &(pc->mouse),
			       1, 12, pc->pic, set_irq,
			       pc, pc_reset_request);
	pc->adlib = adlib_new();
	pc->ne2000 = isa_ne2000_init(0x300, 9, pc->pic, set_irq);

	pc->port92 = 0x2;
	pc->shutdown_state = 0;
	pc->reset_request = 0;
	return pc;
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
typedef struct {
	int width, height;
	SDL_Surface *screen;
	PC *pc;
} Console;

Console *console_init(int width, int height)
{
	Console *s = malloc(sizeof(Console));
	s->width = width;
	s->height = height;
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO);
	s->screen = SDL_SetVideoMode(s->width, s->height, BPP, 0);
	SDL_EnableKeyRepeat(SDL_DEFAULT_REPEAT_DELAY,
			    SDL_DEFAULT_REPEAT_INTERVAL);
	return s;
}

static void redraw(void *opaque,
		   int x, int y, int w, int h)
{
	Console *s = opaque;
	SDL_Flip(s->screen);
	SDL_PumpEvents();
}

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
	int keycode;
	keycode = ev->keysym.scancode;
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
		if (keycode == 0x3a || keycode ==0x45) {
			/* SDL does not generate key up for numlock & caps lock */
			ps2_put_keycode(pc->kbd, 1, keycode);
			ps2_put_keycode(pc->kbd, 0, keycode);
		} else {
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

	while (SDL_PollEvent(&ev)) {
		switch (ev.type) {
		case SDL_KEYDOWN:
		case SDL_KEYUP:
			sdl_handle_key_event(&(ev.key), s->pc);
			break;
		case SDL_MOUSEMOTION:
			sdl_handle_mouse_motion_event(&ev, s->pc);
			break;
		case SDL_MOUSEBUTTONDOWN:
		case SDL_MOUSEBUTTONUP:
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
	audio_spec.channels = 1;
	audio_spec.samples = 1024;
	audio_spec.callback = adlib_callback;
	audio_spec.userdata = console->pc->adlib;
	SDL_OpenAudio(&audio_spec, 0);
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

	if (pc->kernel && pc->kernel[0]) {
		int start_addr = 0x10000;
		int cmdline_addr = 0xf800;
		int kernel_size = load(pc, pc->kernel, 0x00100000);
		int initrd_size = 0;
		if (pc->initrd && pc->initrd[0])
			initrd_size = load(pc, pc->initrd, 0x00400000);
		if (pc->cmdline && pc->cmdline[0])
			strcpy(pc->cpu->phys_mem + cmdline_addr, pc->cmdline);
		else
			strcpy(pc->cpu->phys_mem + cmdline_addr, "");

		load(pc, pc->linuxstart, start_addr);
		cpui386_reset_pm(pc->cpu, 0x10000);
		pc->cpu->gpr[0] = pc->phys_mem_size;
		pc->cpu->gpr[3] = initrd_size;
		pc->cpu->gpr[1] = cmdline_addr;
		pc->cpu->gpr[2] = kernel_size;
	} else {
		cpui386_reset(pc->cpu);
	}

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
		} else if (NAME("hdb")) {
			conf->disks[1] = strdup(value);
		} else if (NAME("hdc")) {
			conf->disks[2] = strdup(value);
		} else if (NAME("hdd")) {
			conf->disks[3] = strdup(value);
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
extern void *theadlib;
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
	conf.mem_size = 7 * 1024 * 1024 + 460 * 1024 - 28 * 1024;
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
	theadlib = pc->adlib;

	load_bios_and_reset(pc);

	pc->boot_start_time = get_uticks();
	for (; pc->shutdown_state != 8;) {
		long last = pc->cpu->cycle;
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
	long k = 0;
	for (; pc->shutdown_state != 8;) {
		long last = pc->cpu->cycle;
		pc_step(pc);
#ifndef USEKVM
		k += pc->cpu->cycle - last;
		if (k >= 4096) {
			usleep(0);
//			usleep(4000);
			k = 0;
		}
#endif
	}
	return 0;
}
#endif
