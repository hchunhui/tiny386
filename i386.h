#ifndef I386_H
#define I386_H

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

typedef u32 uword;
typedef s32 sword;

typedef struct FPU FPU;

typedef struct {
	union {
		uword gpr[8];
		union {
			u32 r32;
			u16 r16;
			u8 r8[2];
		} gprx[8];
	};
	uword ip, next_ip;
	uword flags;
	uword flags_mask;
	int cpl;
	bool halt;

	struct {
		uword sel;
		uword base;
		uword limit;
		uword flags;
	} seg[8];

	struct {
		uword base;
		uword limit;
	} idt, gdt;

	uword cr0;
	uword cr2;
	uword cr3;

	uword dr[8];

	struct {
		uword lpgno;
		uword paddr;
	} ifetch;

	struct {
		int op;
		uword dst;
		uword dst2;
		uword src1;
		uword src2;
		uword mask;
	} cc;

	struct {
		int size;
		struct tlb_entry {
			uword lpgno;
			uword pte;
			u8 *ppte;
		} *tab;
	} tlb;

	char *phys_mem;
	long phys_mem_size;

	long cycle;

	int excno;
	uword excerr;

	bool intr;
	void *pic;
	int (*pic_read_irq)(void *);

	void *io;
	u8 (*io_read8)(void *, int);
	void (*io_write8)(void *, int, u8);
	u16 (*io_read16)(void *, int);
	void (*io_write16)(void *, int, u16);
	u32 (*io_read32)(void *, int);
	void (*io_write32)(void *, int, u32);

	void *iomem;
	u8 (*iomem_read8)(void *, uword);
	void (*iomem_write8)(void *, uword, u8);
	u16 (*iomem_read16)(void *, uword);
	void (*iomem_write16)(void *, uword, u16);
	u32 (*iomem_read32)(void *, uword);
	void (*iomem_write32)(void *, uword, u32);

	FPU *fpu;
} CPUI386;

CPUI386 *cpui386_new(int gen, char *phys_mem, long phys_mem_size);
void cpui386_enable_fpu(CPUI386 *cpu);
void cpui386_reset(CPUI386 *cpu);
void cpui386_reset_pm(CPUI386 *cpu, uint32_t start_addr);
void cpui386_step(CPUI386 *cpu, int stepcount);

bool cpu_load8(CPUI386 *cpu, int seg, uword addr, u8 *res);
bool cpu_store8(CPUI386 *cpu, int seg, uword addr, u8 val);
bool cpu_load16(CPUI386 *cpu, int seg, uword addr, u16 *res);
bool cpu_store16(CPUI386 *cpu, int seg, uword addr, u16 val);
bool cpu_load32(CPUI386 *cpu, int seg, uword addr, u32 *res);
bool cpu_store32(CPUI386 *cpu, int seg, uword addr, u32 val);
void cpu_setax(CPUI386 *cpu, u16 ax);
u16 cpu_getax(CPUI386 *cpu);
void cpu_setexc(CPUI386 *cpu, int excno, uword excerr);
void cpu_abort(CPUI386 *cpu, int code);

#endif /* I386_H */
