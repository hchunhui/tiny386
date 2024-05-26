#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include "i8259.h"
#include "i8254.h"
#include "ide.h"

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

typedef u32 uword;
typedef s32 sword;
#define wordmask ((uword) ((sword) -1))

enum {
	EX_DE,
	EX_DB,
	EX_NMI,
	EX_BP,
	EX_OF,
	EX_BR,
	EX_UD,
	EX_NM,
	EX_DF,
	EX_INT9,
	EX_TS,
	EX_NP,
	EX_SS,
	EX_GP,
	EX_PF,
};

enum {
	CF = 0x1,
	/* 1 0x2 */
	PF = 0x4,
	/* 0 0x8 */
	AF = 0x10,
	/* 0 0x20 */
	ZF = 0x40,
	SF = 0x80,
	TF = 0x100,
	IF = 0x200,
	DF = 0x400,
	OF = 0x800,
	IOPL = 0x3000,
	NT = 0x4000,
	/* 0 0x8000 */
	RF = 0x10000,
	VM = 0x20000,
};

enum {
	SEG_ES = 0,
	SEG_CS,
	SEG_SS,
	SEG_DS,
	SEG_FS,
	SEG_GS,
	SEG_LDT,
	SEG_TR,
};

typedef struct {
	uword gpr[8];
	uword ip, next_ip;
	uword flags;
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
} CPUI386;
#define REGi(x) (cpu->gpr[x])
#define SEGi(x) (cpu->seg[x].sel)

void cpu_debug(CPUI386 *cpu);

static void cpu_abort(CPUI386 *cpu, int code)
{
	fprintf(stderr, "abort: %d %x cycle %ld\n", code, code, cpu->cycle);
	cpu_debug(cpu);
	abort();
}

static uword sext8(u8 a)
{
	return (sword) (s8) a;
}

static uword sext16(u16 a)
{
	return (sword) (s16) a;
}

static uword sext32(u32 a)
{
	return (sword) (s32) a;
}

enum {
	CC_AAA, CC_AAS, CC_AAD, CC_AAM, CC_DAA, CC_DAS,
	CC_ADC, CC_ADD,	CC_SBB, CC_SUB, CC_NEG, CC_DEC, CC_INC,
	CC_IMUL8, CC_IMUL16, CC_IMUL32,	CC_MUL8, CC_MUL16, CC_MUL32,
	CC_RCL, CC_RCR, CC_ROL, CC_ROR, CC_SAR, CC_SHL, CC_SHR,
	CC_SHLD, CC_SHRD, CC_BSF, CC_BSR,
	CC_AND, CC_OR, CC_XOR,
};

static int get_CF(CPUI386 *cpu)
{
	if (cpu->cc.mask & CF) {
		switch(cpu->cc.op) {
		case CC_AAA:
		case CC_AAS:
			cpu_abort(cpu, -1);
		case CC_AAD:
		case CC_AAM:
			return 0;
		case CC_DAA:
		case CC_DAS:
			cpu_abort(cpu, -1);
		case CC_ADC:
			return cpu->cc.dst <= cpu->cc.src2;
		case CC_ADD:
			return cpu->cc.dst < cpu->cc.src2;
		case CC_SBB:
			return cpu->cc.src1 <= cpu->cc.src2;
		case CC_SUB:
			return cpu->cc.src1 < cpu->cc.src2;
		case CC_NEG:
			return cpu->cc.dst != 0;
		case CC_DEC:
		case CC_INC:
			cpu_abort(cpu, -2); // should not happen
		case CC_IMUL8:
			return sext8(cpu->cc.dst) != cpu->cc.dst;
		case CC_IMUL16:
			return sext16(cpu->cc.dst) != cpu->cc.dst;
		case CC_IMUL32:
			return (sext32(cpu->cc.dst) >> 31) != cpu->cc.dst2;
		case CC_MUL8:
			return (cpu->cc.dst >> 8) != 0;
		case CC_MUL16:
			return (cpu->cc.dst >> 16) != 0;
		case CC_MUL32:
			return (cpu->cc.dst2) != 0;
		case CC_RCL:
		case CC_RCR:
		case CC_ROL:
		case CC_ROR:
		case CC_SHL:
		case CC_SHR:
		case CC_SAR:
			return cpu->cc.dst2 & 1;
		case CC_SHLD:
			return cpu->cc.dst2 >> 31;
		case CC_SHRD:
			return cpu->cc.dst2 & 1;
		case CC_BSF:
		case CC_BSR:
			return 0;
		case CC_AND:
		case CC_OR:
		case CC_XOR:
			return 0;
		}
	} else {
		return !!(cpu->flags & CF);
	}
	abort();
}

const static u8 parity_tab[256] = {
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

static int get_PF(CPUI386 *cpu)
{
	if (cpu->cc.mask & PF) {
		return parity_tab[cpu->cc.dst & 0xff];
	} else {
		return !!(cpu->flags & PF);
	}
}

static int get_AF(CPUI386 *cpu)
{
	if (cpu->cc.mask & AF) {
		switch(cpu->cc.op) {
		case CC_AAA:
		case CC_AAS:
			cpu_abort(cpu, -1);
		case CC_AAD:
		case CC_AAM:
			return 0;
		case CC_DAA:
		case CC_DAS:
			cpu_abort(cpu, -1);
		case CC_ADC:
		case CC_ADD:
		case CC_SBB:
		case CC_SUB:
			return !!((cpu->cc.src1 ^ cpu->cc.src2 ^ cpu->cc.dst) >> 4);
		case CC_NEG:
			return (cpu->cc.dst & 0xf) == 0; //VERIFY
		case CC_DEC:
			return (cpu->cc.dst & 0xf) == 0xf;
		case CC_INC:
			return (cpu->cc.dst & 0xf) == 0;
		case CC_IMUL8: case CC_IMUL16: case CC_IMUL32:
		case CC_MUL8: case CC_MUL16: case CC_MUL32:
			return 0;
		case CC_RCL:
		case CC_RCR:
		case CC_ROL:
		case CC_ROR:
		case CC_SAR:
		case CC_SHL:
		case CC_SHR:
		case CC_SHLD:
		case CC_SHRD:
		case CC_BSF:
		case CC_BSR:
		case CC_AND:
		case CC_OR:
		case CC_XOR:
			return 0;
		}
	} else {
		return !!(cpu->flags & AF);
	}
	abort();
}

static int get_ZF(CPUI386 *cpu)
{
	if (cpu->cc.mask & ZF) {
		return cpu->cc.dst == 0;
	} else {
		return !!(cpu->flags & ZF);
	}
}

static int get_SF(CPUI386 *cpu)
{
	if (cpu->cc.mask & SF) {
		return cpu->cc.dst >> (sizeof(uword) * 8 - 1);
	} else {
		return !!(cpu->flags & SF);
	}
}

static int get_OF(CPUI386 *cpu)
{
	if (cpu->cc.mask & OF) {
		switch(cpu->cc.op) {
		case CC_AAA:
		case CC_AAS:
		case CC_AAD:
		case CC_AAM:
		case CC_DAA:
		case CC_DAS:
			return 0;
		case CC_ADC:
		case CC_ADD:
			return (~(cpu->cc.src1 ^ cpu->cc.src2) & (cpu->cc.dst ^ cpu->cc.src2)) >> (sizeof(uword) * 8 - 1);
		case CC_SBB:
		case CC_SUB:
			return ((cpu->cc.src1 ^ cpu->cc.src2) & (cpu->cc.dst ^ cpu->cc.src1)) >> (sizeof(uword) * 8 - 1);
		case CC_NEG:
			return cpu->cc.dst == 1 << (sizeof(uword) * 8 - 1);
		case CC_DEC:
			return cpu->cc.dst == ~(1 << (sizeof(uword) * 8 - 1));
		case CC_INC:
			return cpu->cc.dst == 1 << (sizeof(uword) * 8 - 1);
		case CC_IMUL8: case CC_IMUL16: case CC_IMUL32:
		case CC_MUL8: case CC_MUL16: case CC_MUL32:
			return get_CF(cpu);
		case CC_RCL:
		case CC_RCR:
		case CC_ROL:
			return (cpu->cc.dst >> (sizeof(uword) * 8 - 1)) ^ (cpu->cc.dst2 & 1);
		case CC_ROR:
			return (cpu->cc.dst ^ (cpu->cc.dst << 1)) >> (sizeof(uword) * 8 - 1);
		case CC_SAR:
			return 0;
		case CC_SHL:
			return (cpu->cc.dst >> (sizeof(uword) * 8 - 1)) ^ (cpu->cc.dst2 & 1);
		case CC_SHR:
			return (cpu->cc.src1 >> (sizeof(uword) * 8 - 1));
		case CC_SHLD:
		case CC_SHRD:
			return (cpu->cc.src1 ^ cpu->cc.dst) >> (sizeof(uword) * 8 - 1);
		case CC_BSF:
		case CC_BSR:
			return 0;
		case CC_AND:
		case CC_OR:
		case CC_XOR:
			return 0;
		}
		cpu_abort(cpu, -1);
	} else {
		return !!(cpu->flags & OF);
	}
	abort();
}

static void refresh_flags(CPUI386 *cpu)
{
	if (cpu->cc.mask == 0)
		return;
	if (get_CF(cpu))
		cpu->flags |= CF;
	else
		cpu->flags &= ~CF;

	if (get_PF(cpu))
		cpu->flags |= PF;
	else
		cpu->flags &= ~PF;

	if (get_AF(cpu))
		cpu->flags |= AF;
	else
		cpu->flags &= ~AF;

	if (get_ZF(cpu))
		cpu->flags |= ZF;
	else
		cpu->flags &= ~ZF;

	if (get_SF(cpu))
		cpu->flags |= SF;
	else
		cpu->flags &= ~SF;

	if (get_OF(cpu))
		cpu->flags |= OF;
	else
		cpu->flags &= ~OF;
}

#define CR0_PG (1<<31)
#define tlb_size 512
typedef struct {
	enum {
		ADDR_OK1,
		ADDR_OK2,
	} res;
	uword addr1;
	uword addr2;
} OptAddr;

static void tlb_clear(CPUI386 *cpu)
{
	for (int i = 0; i < tlb_size; i++) {
		cpu->tlb.tab[i].lpgno = -1;
	}
	cpu->ifetch.lpgno = -1;
}

static bool tlb_refill(CPUI386 *cpu, struct tlb_entry *ent, uword lpgno)
{
	uword base_addr = cpu->cr3 & ~0xfff;
	uword i = lpgno >> 10;
	uword j = lpgno & 1023;

	u8 *mem = (u8 *) cpu->phys_mem;
	uword pde = mem[base_addr + i * 4] |
		(mem[base_addr + i * 4 + 1] << 8) |
		(mem[base_addr + i * 4 + 2] << 16) |
		(mem[base_addr + i * 4 + 3] << 24);
	if (!(pde & 1))
		return false;
	uword base_addr2 = pde & ~0xfff;
	uword pte = mem[base_addr2 + j * 4] |
		(mem[base_addr2 + j * 4 + 1] << 8) |
		(mem[base_addr2 + j * 4 + 2] << 16) |
		(mem[base_addr2 + j * 4 + 3] << 24);
	if (!(pte & 1))
		return false;
	ent->lpgno = lpgno;
	ent->pte = pte;
	return true;
}

#define TRY(f) if(!(f)) return false

static bool translate_slow(CPUI386 *cpu, OptAddr *res, int rwm, uword laddr, int size)
{
	if (cpu->cr0 & CR0_PG) {
		uword lpgno = laddr >> 12;
		struct tlb_entry *ent = &(cpu->tlb.tab[lpgno % tlb_size]);
		if (ent->lpgno != lpgno) {
			if (!tlb_refill(cpu, ent, lpgno)) {
				cpu->cr2 = laddr;
				cpu->excno = EX_PF;
				cpu->excerr = 0;
				if (cpu->seg[SEG_CS].sel & 3)
					cpu->excerr |= 4;
				return false;
			}
		}
		// TODO WP bit
		if ((rwm & 2) && !(ent->pte & 2)) {
			cpu->cr2 = laddr;
			cpu->excno = EX_PF;
			cpu->excerr = 3;
			if (cpu->seg[SEG_CS].sel & 3)
				cpu->excerr |= 4;
			return false;
		}
		res->res = ADDR_OK1;
		res->addr1 = (ent->pte & ~0xfff) | (laddr & 0xfff);

		if ((laddr & 0xfff) > 0x1000 - size) {
			lpgno++;
			ent = &(cpu->tlb.tab[lpgno % tlb_size]);
			if (ent->lpgno != lpgno) {
				if (!tlb_refill(cpu, ent, lpgno)) {
					cpu->cr2 = lpgno << 12;
					cpu->excno = EX_PF;
					cpu->excerr = 0;
					if (cpu->seg[SEG_CS].sel & 3)
						cpu->excerr |= 4;
					return false;
				}
			}
			// TODO WP bit
			if ((rwm & 2) && !(ent->pte & 2)) {
				cpu->cr2 = lpgno << 12;
				cpu->excno = EX_PF;
				cpu->excerr = 3;
				if (cpu->seg[SEG_CS].sel & 3)
					cpu->excerr |= 4;
				return false;
			}
			res->res = ADDR_OK2;
			res->addr2 = ent->pte & ~0xfff;
		}
	} else {
		res->res = ADDR_OK1;
		res->addr1 = laddr;
	}
	return true;
}

static bool translate(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr, int size)
{
	uword laddr = cpu->seg[seg].base + addr;
	if (laddr & 3)
		return translate_slow(cpu, res, rwm, laddr, size);
	if (cpu->cr0 & CR0_PG) {
		uword lpgno = laddr >> 12;
		struct tlb_entry *ent = &(cpu->tlb.tab[lpgno % tlb_size]);
		if (ent->lpgno != lpgno) {
			if (!tlb_refill(cpu, ent, lpgno)) {
				cpu->cr2 = laddr;
				cpu->excno = EX_PF;
				cpu->excerr = 0;
				if (cpu->seg[SEG_CS].sel & 3)
					cpu->excerr |= 4;
				return false;
			}
		}
		// TODO WP bit
		if ((rwm & 2) && !(ent->pte & 2)) {
			cpu->cr2 = laddr;
			cpu->excno = EX_PF;
			cpu->excerr = 3;
			if (cpu->seg[SEG_CS].sel & 3)
				cpu->excerr |= 4;
			return false;
		}
		res->res = ADDR_OK1;
		res->addr1 = (ent->pte & ~0xfff) | (laddr & 0xfff);
	} else {
		res->res = ADDR_OK1;
		res->addr1 = laddr;
	}
	return true;
}

static bool translate8(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr)
{
	uword laddr = cpu->seg[seg].base + addr;
	if (cpu->cr0 & CR0_PG) {
		uword lpgno = laddr >> 12;
		struct tlb_entry *ent = &(cpu->tlb.tab[lpgno % tlb_size]);
		if (ent->lpgno != lpgno) {
			if (!tlb_refill(cpu, ent, lpgno)) {
				cpu->cr2 = laddr;
				cpu->excno = EX_PF;
				cpu->excerr = 0;
				if (cpu->seg[SEG_CS].sel & 3)
					cpu->excerr |= 4;
				return false;
			}
		}
		// TODO WP bit
		if ((rwm & 2) && !(ent->pte & 2)) {
			cpu->cr2 = laddr;
			cpu->excno = EX_PF;
			cpu->excerr = 3;
			if (cpu->seg[SEG_CS].sel & 3)
				cpu->excerr |= 4;
			return false;
		}
		res->res = ADDR_OK1;
		res->addr1 = (ent->pte & ~0xfff) | (laddr & 0xfff);
	} else {
		res->res = ADDR_OK1;
		res->addr1 = laddr;
	}
	return true;
}

static bool translate16(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr)
{
	return translate(cpu, res, rwm, seg, addr, 2);
}

static bool translate32(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr)
{
	return translate(cpu, res, rwm, seg, addr, 4);
}

static u8 load8(CPUI386 *cpu, OptAddr *res)
{
	return ((u8 *) cpu->phys_mem)[res->addr1];
}

static u16 load16(CPUI386 *cpu, OptAddr *res)
{
	u8 *mem = (u8 *) cpu->phys_mem;
	if (res->res == ADDR_OK1)
		return mem[res->addr1] | (mem[res->addr1 + 1] << 8);
	else
		return mem[res->addr1] | (mem[res->addr2] << 8);
}

static u32 load32(CPUI386 *cpu, OptAddr *res)
{
	u8 *mem = (u8 *) cpu->phys_mem;
	if (res->res == ADDR_OK1) {
		u32 val = mem[res->addr1] | (mem[res->addr1 + 1] << 8) |
			(mem[res->addr1 + 2] << 16) | (mem[res->addr1 + 3] << 24);
		return val;
	} else {
		switch(res->addr1 & 0xf) {
		case 0xf:
			return mem[res->addr1] | (mem[res->addr2] << 8) |
			(mem[res->addr2 + 1] << 16) | (mem[res->addr2 + 2] << 24);
		case 0xe:
			return mem[res->addr1] | (mem[res->addr1 + 1] << 8) |
			(mem[res->addr2] << 16) | (mem[res->addr2 + 1] << 24);
		case 0xd:
			return mem[res->addr1] | (mem[res->addr1 + 1] << 8) |
			(mem[res->addr1 + 2] << 16) | (mem[res->addr2] << 24);
		}
	}
	abort();
}

static void store8(CPUI386 *cpu, OptAddr *res, u8 val)
{
	((u8 *) cpu->phys_mem)[res->addr1] = val;
}

static void store16(CPUI386 *cpu, OptAddr *res, u16 val)
{
	u8 *mem = (u8 *) cpu->phys_mem;
	if (res->res == ADDR_OK1) {
		mem[res->addr1] = val;
		mem[res->addr1 + 1] = val >> 8;
	} else {
		mem[res->addr1] = val;
		mem[res->addr2] = val >> 8;
	}
}

static void store32(CPUI386 *cpu, OptAddr *res, u32 val)
{
	u8 *mem = (u8 *) cpu->phys_mem;
	if (res->res == ADDR_OK1) {
		mem[res->addr1] = val;
		mem[res->addr1 + 1] = val >> 8;
		mem[res->addr1 + 2] = val >> 16;
		mem[res->addr1 + 3] = val >> 24;
	} else {
		switch(res->addr1 & 0xf) {
		case 0xf:
			mem[res->addr1] = val;
			mem[res->addr2] = val >> 8;
			mem[res->addr2 + 1] = val >> 16;
			mem[res->addr2 + 2] = val >> 24;
			break;
		case 0xe:
			mem[res->addr1] = val;
			mem[res->addr1 + 1] = val >> 8;
			mem[res->addr2] = val >> 16;
			mem[res->addr2 + 1] = val >> 24;
			break;
		case 0xd:
			mem[res->addr1] = val;
			mem[res->addr1 + 1] = val >> 8;
			mem[res->addr1 + 2] = val >> 16;
			mem[res->addr2] = val >> 24;
			break;
		}
	}
}

static bool peek8(CPUI386 *cpu, u8 *val)
{
	uword laddr = cpu->seg[SEG_CS].base + cpu->next_ip;
	uword lpgno = laddr >> 12;
	uword lpgoff = laddr & 4095;
	if (lpgno == cpu->ifetch.lpgno) {
		u8 *mem = (u8 *) cpu->phys_mem;
		*val = mem[cpu->ifetch.paddr | lpgoff];
		return true;
	}
	OptAddr res;
	TRY(translate8(cpu, &res, 1, SEG_CS, cpu->next_ip));
	*val = load8(cpu, &res);
	cpu->ifetch.lpgno = lpgno;
	cpu->ifetch.paddr = res.addr1 >> 12 << 12;
	return true;
}

static bool fetch8(CPUI386 *cpu, u8 *val)
{
	TRY(peek8(cpu, val));
	cpu->next_ip++;
	return true;
}

static bool fetch16(CPUI386 *cpu, u16 *val)
{
	OptAddr res;
	TRY(translate16(cpu, &res, 1, SEG_CS, cpu->next_ip));
	*val = load16(cpu, &res);
	cpu->next_ip += 2;
	return true;
}

static bool fetch32(CPUI386 *cpu, u32 *val)
{
	uword laddr = cpu->seg[SEG_CS].base + cpu->next_ip;
	uword lpgno = laddr >> 12;
	uword lpgoff = laddr & 4095;
	if (lpgoff <= 4092 && lpgno == cpu->ifetch.lpgno) {
		u8 *mem = (u8 *) cpu->phys_mem;
		uword addr = cpu->ifetch.paddr | lpgoff;
		*val = mem[addr] | (mem[addr + 1] << 8) |
			(mem[addr + 2] << 16) | (mem[addr + 3] << 24);
	} else {
		OptAddr res;
		TRY(translate32(cpu, &res, 1, SEG_CS, cpu->next_ip));
		*val = load32(cpu, &res);
	}
	cpu->next_ip += 4;
	return true;
}

static bool modsib(CPUI386 *cpu, int mod, int rm, uword *addr)
{
	if (rm == 4) {
		u8 sib;
		TRY(fetch8(cpu, &sib));
		int b = sib & 7;
		if (b == 5 && mod == 0) {
			TRY(fetch32(cpu, addr));
		} else {
			*addr = REGi(b);
		}
		int i = (sib >> 3) & 7;
		if (i != 4)
			*addr += REGi(i) << (sib >> 6);
	} else if (rm == 5 && mod == 0) {
		TRY(fetch32(cpu, addr));
	} else {
		*addr = REGi(rm);
	}
	if (mod == 1) {
		u8 imm8;
		TRY(fetch8(cpu, &imm8));
		*addr += (s8) imm8;
	} else if (mod == 2) {
		u32 imm32;
		TRY(fetch32(cpu, &imm32));
		*addr += (s32) imm32;
	}
	return true;
}

static bool set_seg(CPUI386 *cpu, int seg, int sel)
{
	OptAddr meml;
	uword off = sel & ~0x7;
	uword base;
	uword limit;
	if (sel & 0x4) {
		base = cpu->seg[SEG_LDT].base;
		limit = cpu->seg[SEG_LDT].limit;
	} else {
		base = cpu->gdt.base;
		limit = cpu->gdt.limit;
	}
	if (off > limit) {
		cpu->excno = EX_GP;
		return false;
	}
	TRY(translate_slow(cpu, &meml, 1, base + off, 4));
	uword w1 = load32(cpu, &meml);
	TRY(translate_slow(cpu, &meml, 1, base + off + 4, 4));
	uword w2 = load32(cpu, &meml);
	cpu->seg[seg].sel = sel;
	cpu->seg[seg].base = (w1 >> 16) | ((w2 & 0xff) << 16) | (w2 & 0xff000000);
	if (w2 & 0x008000)
		cpu->seg[seg].limit = ((w1 & 0xffff) << 12) | 0xfff;
	else
		cpu->seg[seg].limit = w1 & 0xffff;
	return true;
}

#define ARGCOUNT_IMPL(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, ...) _17
#define ARGCOUNT(...) ARGCOUNT_IMPL(~, ## __VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define PASTE0(a, b) a ## b
#define PASTE(a, b) PASTE0(a, b)

#define C_1(_1)      CX(_1)
#define C_2(_1, ...) CX(_1) C_1(__VA_ARGS__)
#define C_3(_1, ...) CX(_1) C_2(__VA_ARGS__)
#define C_4(_1, ...) CX(_1) C_3(__VA_ARGS__)
#define C_5(_1, ...) CX(_1) C_4(__VA_ARGS__)
#define C_6(_1, ...) CX(_1) C_5(__VA_ARGS__)
#define C_7(_1, ...) CX(_1) C_6(__VA_ARGS__)
#define C_8(_1, ...) CX(_1) C_7(__VA_ARGS__)
#define C_9(_1, ...) CX(_1) C_8(__VA_ARGS__)
#define C_10(_1, ...) CX(_1) C_9(__VA_ARGS__)
#define C_11(_1, ...) CX(_1) C_10(__VA_ARGS__)
#define C_12(_1, ...) CX(_1) C_11(__VA_ARGS__)
#define C_13(_1, ...) CX(_1) C_12(__VA_ARGS__)
#define C_14(_1, ...) CX(_1) C_13(__VA_ARGS__)
#define C_15(_1, ...) CX(_1) C_14(__VA_ARGS__)
#define C_16(_1, ...) CX(_1) C_15(__VA_ARGS__)
#define C(...) PASTE(C_, ARGCOUNT(__VA_ARGS__))(__VA_ARGS__)

#define I(...)
#define I2(...)
#define IG1b(...)
#define IG1v(...)
#define IG1vIb(...)
#define IG2b(...)
#define IG2v(...)
#define IG2b1(...)
#define IG2v1(...)
#define IG2bC(...)
#define IG2vC(...)
#define IG3b(...)
#define IG3v(...)
#define IG4(...)
#define IG5(...)
#define IG6(...)
#define IG7(...)
#define IG8(...)

/*
 * addressing modes
 */
#define _(rwm, inst) inst()

#define E_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, laddr ## BIT, saddr ## BIT) \
	}

#define Eb(...) E_helper(8, , __VA_ARGS__)
#define Ev(...) if (opsz16) { E_helper(16, w, __VA_ARGS__) } else { E_helper(32, d, __VA_ARGS__) }

#define EG_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, reg, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, reg, laddr ## BIT, saddr ## BIT, lreg ## BIT, sreg ## BIT) \
	}

#define EbGb(...) EG_helper(8, , __VA_ARGS__)
#define EvGv(...) if (opsz16) { EG_helper(16, w, __VA_ARGS__) } else { EG_helper(32, d, __VA_ARGS__) }

#define BTEG_helper(BIT, BYTE, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, reg, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		addr += lreg ## BIT(reg) / BIT * BYTE; \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, reg, laddr ## BIT, saddr ## BIT, lreg ## BIT, sreg ## BIT) \
	}

#define BTEvGv(...) if (opsz16) { BTEG_helper(16, 2, w, __VA_ARGS__) } else { BTEG_helper(32, 4, d, __VA_ARGS__) }

#define EGIb_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		INST ## SUFFIX(rm, reg, imm8, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(fetch8(cpu, &imm8)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, reg, imm8, laddr ## BIT, saddr ## BIT, lreg ## BIT, sreg ## BIT, limm, 0) \
	}

#define EvGvIb(...) if (opsz16) { EGIb_helper(16, w, __VA_ARGS__) } else { EGIb_helper(32, d, __VA_ARGS__) }

#define EGCL_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, reg, 1, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT, lreg8, sreg8) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, reg, 1, laddr ## BIT, saddr ## BIT, lreg ## BIT, sreg ## BIT, lreg8, sreg8) \
	}

#define EvGvCL(...) if (opsz16) { EGCL_helper(16, w, __VA_ARGS__) } else { EGCL_helper(32, d, __VA_ARGS__) }

#define EI_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u ## BIT imm ## BIT; \
	if (mod == 3) { \
		TRY(fetch ## BIT(cpu, &imm ## BIT)); \
		INST ## SUFFIX(rm, imm ## BIT, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(fetch ## BIT(cpu, &imm ## BIT)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, imm ## BIT, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define EbIb(...) EI_helper(8, , __VA_ARGS__)
#define EvIv(...) if (opsz16) { EI_helper(16, w, __VA_ARGS__) } else { EI_helper(32, d, __VA_ARGS__) }

#define EIb_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	u ## BIT imm ## BIT; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		imm ## BIT = (s ## BIT) ((s8) imm8); \
		INST ## SUFFIX(rm, imm ## BIT, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(fetch8(cpu, &imm8)); \
		imm ## BIT = (s ## BIT) ((s8) imm8); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, imm ## BIT, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define EvIb(...) if (opsz16) { EIb_helper(16, w, __VA_ARGS__) } else { EIb_helper(32, d, __VA_ARGS__) }

#define BTEIb_helper(BIT, BYTE, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	u ## BIT imm ## BIT; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		imm ## BIT = (s ## BIT) ((s8) imm8); \
		INST ## SUFFIX(rm, imm ## BIT, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(fetch8(cpu, &imm8)); \
		imm ## BIT = (s ## BIT) ((s8) imm8); \
		addr += imm ## BIT / BIT * BYTE; \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, imm ## BIT, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define BTEvIb(...) if (opsz16) { BTEIb_helper(16, 2, w, __VA_ARGS__) } else { BTEIb_helper(32, 4, d, __VA_ARGS__) }

#define E1_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, 1, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, 1, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define Eb1(...) E1_helper(8, , __VA_ARGS__)
#define Ev1(...) if (opsz16) { E1_helper(16, w, __VA_ARGS__) } else { E1_helper(32, d, __VA_ARGS__) }

#define ECL_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, 1, lreg ## BIT, sreg ## BIT, lreg8, sreg8) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, 1, laddr ## BIT, saddr ## BIT, lreg8, sreg8) \
	}

#define EbCL(...) ECL_helper(8, , __VA_ARGS__)
#define EvCL(...) if (opsz16) { ECL_helper(16, w, __VA_ARGS__) } else { ECL_helper(32, d, __VA_ARGS__) }

#define GE_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(reg, rm, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(reg, &meml, lreg ## BIT, sreg ## BIT, laddr ## BIT, saddr ## BIT) \
	}

#define GbEb(...) GE_helper(8, , __VA_ARGS__)
#define GvEv(...) if (opsz16) { GE_helper(16, w, __VA_ARGS__) } else { GE_helper(32, d, __VA_ARGS__) }

#define GvM(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## d(reg, rm, lreg32, sreg32, lreg32, sreg32) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		INST ## d(reg, addr, lreg32, sreg32, limm32, 0) \
	}
#define GvMp GvM

#define GE_helper2(BIT, SUFFIX, BIT2, SUFFIX2, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX ## SUFFIX2(reg, rm, lreg ## BIT, sreg ## BIT, lreg ## BIT2, sreg ## BIT2) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate ## BIT2(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX ## SUFFIX2(reg, &meml, lreg ## BIT, sreg ## BIT, laddr ## BIT2, saddr ## BIT2) \
	}

#define GvEb(...) if (opsz16) { GE_helper2(16, w, 8, b, __VA_ARGS__) } else { GE_helper2(32, d, 8, b, __VA_ARGS__) }
#define GvEw(...) if (opsz16) { GE_helper2(16, w, 16, w, __VA_ARGS__) } else { GE_helper2(32, d, 16, w, __VA_ARGS__) }

#define GEI_helperI2(BIT, SUFFIX, BIT2, SUFFIX2, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		u ## BIT2 imm ## BIT2; \
		TRY(fetch ## BIT2(cpu, &imm ## BIT2)); \
		INST ## SUFFIX ## I ## SUFFIX2(reg, rm, imm ## BIT2, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		u ## BIT2 imm ## BIT2; \
		TRY(fetch ## BIT2(cpu, &imm ## BIT2)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX ## I ## SUFFIX2(reg, &meml, imm ## BIT2, lreg ## BIT, sreg ## BIT, laddr ## BIT, saddr ## BIT) \
	}

#define GvEvIb(...) if (opsz16) { GEI_helperI2(16, w, 8, b, __VA_ARGS__) } else { GEI_helperI2(32, d, 8, b, __VA_ARGS__) }
#define GvEvIv(...) if (opsz16) { GEI_helperI2(16, w, 16, w, __VA_ARGS__) } else { GEI_helperI2(32, d, 32, d, __VA_ARGS__) }

#define ALIb(rwm, INST) \
	u8 imm8; \
	TRY(fetch8(cpu, &imm8)); \
	INST(0, imm8, lreg8, sreg8, limm, 0)

#define AXIb(rwm, INST) \
	if (opsz16) { \
		u8 imm8; \
		TRY(fetch8(cpu, &imm8)); \
		INST ## w(0, imm8, lreg16, sreg16, limm, 0) \
	} else { \
		u8 imm8; \
		TRY(fetch8(cpu, &imm8)); \
		INST ## d(0, imm8, lreg32, sreg32, limm, 0) \
	}

#define IbAL(rwm, INST) \
	u8 imm8; \
	TRY(fetch8(cpu, &imm8)); \
	INST(imm8, 0, limm, 0, lreg8, sreg8)

#define IbAX(rwm, INST) \
	if (opsz16) { \
		u8 imm8; \
		TRY(fetch8(cpu, &imm8)); \
		INST ## w(imm8, 0, limm, 0, lreg16, sreg16) \
	} else { \
		u8 imm8; \
		TRY(fetch8(cpu, &imm8)); \
		INST ## d(imm8, 0, limm, 0, lreg32, sreg32) \
	}

#define DXAL(rwm, INST) \
	INST(2, 0, lreg16, sreg16, lreg8, sreg8)

#define DXAX(rwm, INST) \
	if (opsz16) { \
		INST ## w(2, 0, lreg16, sreg16, lreg16, sreg16)	\
	} else { \
		INST ## d(2, 0, lreg16, sreg16, lreg32, sreg32) \
	}

#define ALDX(rwm, INST) \
	INST(0, 2, lreg8, sreg8, lreg16, sreg16)

#define AXDX(rwm, INST) \
	if (opsz16) { \
		INST ## w(0, 2, lreg16, sreg16, lreg16, sreg16) \
	} else { \
		INST ## d(0, 2, lreg32, sreg32, lreg16, sreg16) \
	}

#define AXIv(rwm, INST) \
	if (opsz16) { \
		u16 imm16; \
		TRY(fetch16(cpu, &imm16)); \
		INST ## w(0, imm16, lreg16, sreg16, limm, 0) \
	} else { \
		u32 imm32; \
		TRY(fetch32(cpu, &imm32)); \
		INST ## d(0, imm32, lreg32, sreg32, limm, 0) \
	}

#define ALOb(rwm, INST) \
	TRY(fetch32(cpu, &addr)); \
	TRY(translate8(cpu, &meml, rwm, curr_seg, addr)); \
	INST(0, &meml, lreg8, sreg8, laddr8, saddr8)

#define AXOv(rwm, INST) \
	TRY(fetch32(cpu, &addr)); \
	if (opsz16) { \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## w(0, &meml, lreg16, sreg16, laddr16, saddr16) \
	} else { \
		TRY(translate32(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## d(0, &meml, lreg32, sreg32, laddr32, saddr32) \
	}

#define ObAL(rwm, INST) \
	TRY(fetch32(cpu, &addr)); \
	TRY(translate8(cpu, &meml, rwm, curr_seg, addr)); \
	INST(&meml, 0, laddr8, saddr8, lreg8, sreg8)

#define OvAX(rwm, INST) \
	TRY(fetch32(cpu, &addr)); \
	if (opsz16) { \
		TRY(translate32(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## w(&meml, 0, laddr16, saddr16, lreg16, sreg16) \
	} else { \
		TRY(translate32(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## d(&meml, 0, laddr32, saddr32, lreg32, sreg32) \
	}

#define PlusRegv(rwm, INST) \
	if (opsz16) { \
		INST ## w((b1 & 7), lreg16, sreg16) \
	} else { \
		INST ## d((b1 & 7), lreg32, sreg32) \
	}

#define PlusRegIb(rwm, INST) \
	u8 imm8; \
	TRY(fetch8(cpu, &imm8)); \
	INST((b1 & 7), imm8, lreg8, sreg8, limm, 0)

#define PlusRegIv(rwm, INST) \
	if (opsz16) { \
		u16 imm16; \
		TRY(fetch16(cpu, &imm16)); \
		INST ## w((b1 & 7), imm16, lreg16, sreg16, limm, 0) \
	} else { \
		u32 imm32; \
		TRY(fetch32(cpu, &imm32)); \
		INST ## d((b1 & 7), imm32, lreg32, sreg32, limm, 0) \
	}

#define Ib(rwm, INST) \
	u8 imm8; \
	TRY(fetch8(cpu, &imm8)); \
	INST(imm8, limm, 0)
#define Jb Ib

#define Iw(rwm, INST) \
	u16 imm16; \
	TRY(fetch16(cpu, &imm16)); \
	INST(imm16, limm, 0)

#define IwIb(rwm, INST) \
	u16 imm16; \
	TRY(fetch16(cpu, &imm16)); \
	u8 imm8; \
	TRY(fetch8(cpu, &imm8)); \
	INST(imm16, imm8, limm, 0, limm, 0)

#define Iv(rwm, INST) \
	if (opsz16) { \
		u16 imm16; \
		TRY(fetch16(cpu, &imm16)); \
		INST ## w(imm16, limm, 0) \
	} else { \
		u32 imm32; \
		TRY(fetch32(cpu, &imm32)); \
		INST ## d(imm32, limm, 0) \
	}

// adsz
#define Jv(rwm, INST) \
	u32 imm32; \
	TRY(fetch32(cpu, &imm32)); \
	INST ## d(imm32, limm, 0)
#define Av Jv

#define Ms(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		cpu->excno = EX_UD; \
		return false; \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		INST(addr) \
	}

#define Ew(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST(rm, lreg16, sreg16) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST(&meml, laddr16, saddr16) \
	}

#define EwSw(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST(rm, reg, lreg16, sreg16, lseg, 0) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST(&meml, reg, laddr16, saddr16, lseg, 0) \
	}

#define SwEw(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST(reg, rm, lseg, 0, lreg16, sreg16) \
	} else { \
		TRY(modsib(cpu, mod, rm, &addr)); \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST(reg, &meml,lseg, 0, laddr16, saddr16) \
	}

#define limm(i) i
#define lreg8(i) ((u8) ((i) > 3 ? REGi((i) - 4) >> 8 : REGi((i))))
#define sreg8(i, v) ((i) > 3 ? \
		     (REGi((i) - 4) = REGi((i) - 4) & (wordmask ^ 0xff00) | ((v) & 0xff) << 8) : \
		     (REGi((i)) = REGi((i)) & (wordmask ^ 0xff) | v & 0xff))
#define lreg16(i) ((u16) REGi((i)))
#define sreg16(i, v) (REGi((i)) = REGi((i)) & (wordmask ^ 0xffff) | v & 0xffff)
#define lreg32(i) ((u32) REGi((i)))
#define sreg32(i, v) (REGi((i)) = REGi((i)) & (wordmask ^ 0xffffffff) | v & 0xffffffff)
#define laddr8(addr) load8(cpu, addr)
#define saddr8(addr, v) store8(cpu, addr, v)
#define laddr16(addr) load16(cpu, addr)
#define saddr16(addr, v) store16(cpu, addr, v)
#define laddr32(addr) load32(cpu, addr)
#define saddr32(addr, v) store32(cpu, addr, v)
#define lseg(i) ((u16) SEGi((i)))

/*
 * instructions
 */
#define ACOP_helper(NAME1, NAME2, BIT, OP, a, b, la, sa, lb, sb) \
	int cf = get_CF(cpu); \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = cpu->cc.src1 OP cpu->cc.src2 OP cf; \
	cpu->cc.op = cf ? CC_ ## NAME1 : CC_ ## NAME2; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define AOP0_helper(NAME, BIT, OP, a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = cpu->cc.src1 OP cpu->cc.src2; \
	cpu->cc.op = CC_ ## NAME; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF;

#define LOP0_helper(NAME, BIT, OP, a, b, la, sa, lb, sb) \
	cpu->cc.dst = sext ## BIT(la(a) OP lb(b)); \
	cpu->cc.op = CC_ ## NAME; \
	cpu->cc.mask = CF | PF | ZF | SF | OF;

#define AOP_helper(NAME1, BIT, OP, a, b, la, sa, lb, sb) \
	AOP0_helper(NAME1, BIT, OP, a, b, la, sa, lb, sb) \
	sa(a, cpu->cc.dst);

#define LOP_helper(NAME1, BIT, OP, a, b, la, sa, lb, sb) \
	LOP0_helper(NAME1, BIT, OP, a, b, la, sa, lb, sb) \
	sa(a, cpu->cc.dst);

#define INCDEC_helper(NAME, BIT, OP, a, la, sa)	\
	int cf = get_CF(cpu); \
	cpu->cc.dst = sext ## BIT(la(a)) OP 1; \
	cpu->cc.op = CC_ ## NAME; \
	if (cf) { \
		cpu->flags |= CF; \
	} else { \
		cpu->flags &= ~CF; \
	} \
	cpu->cc.mask = PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define NEG_helper(BIT, a, la, sa) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.dst = -cpu->cc.src1; \
	cpu->cc.op = CC_NEG; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define ADCb(...) ACOP_helper(ADC, ADD,  8, +, __VA_ARGS__)
#define ADCw(...) ACOP_helper(ADC, ADD, 16, +, __VA_ARGS__)
#define ADCd(...) ACOP_helper(ADC, ADD, 32, +, __VA_ARGS__)
#define SBBb(...) ACOP_helper(SBB, SUB,  8, -, __VA_ARGS__)
#define SBBw(...) ACOP_helper(SBB, SUB, 16, -, __VA_ARGS__)
#define SBBd(...) ACOP_helper(SBB, SUB, 32, -, __VA_ARGS__)
#define ADDb(...) AOP_helper(ADD,  8, +, __VA_ARGS__)
#define ADDw(...) AOP_helper(ADD, 16, +, __VA_ARGS__)
#define ADDd(...) AOP_helper(ADD, 32, +, __VA_ARGS__)
#define SUBb(...) AOP_helper(SUB,  8, -, __VA_ARGS__)
#define SUBw(...) AOP_helper(SUB, 16, -, __VA_ARGS__)
#define SUBd(...) AOP_helper(SUB, 32, -, __VA_ARGS__)
#define ORb(...)  LOP_helper(OR,   8, |, __VA_ARGS__)
#define ORw(...)  LOP_helper(OR,  16, |, __VA_ARGS__)
#define ORd(...)  LOP_helper(OR,  32, |, __VA_ARGS__)
#define ANDb(...) LOP_helper(AND,  8, &, __VA_ARGS__)
#define ANDw(...) LOP_helper(AND, 16, &, __VA_ARGS__)
#define ANDd(...) LOP_helper(AND, 32, &, __VA_ARGS__)
#define XORb(...) LOP_helper(XOR,  8, ^, __VA_ARGS__)
#define XORw(...) LOP_helper(XOR, 16, ^, __VA_ARGS__)
#define XORd(...) LOP_helper(XOR, 32, ^, __VA_ARGS__)
#define CMPb(...)  AOP0_helper(SUB,  8, -, __VA_ARGS__)
#define CMPw(...)  AOP0_helper(SUB, 16, -, __VA_ARGS__)
#define CMPd(...)  AOP0_helper(SUB, 32, -, __VA_ARGS__)
#define TESTb(...) LOP0_helper(AND,  8, &, __VA_ARGS__)
#define TESTw(...) LOP0_helper(AND, 16, &, __VA_ARGS__)
#define TESTd(...) LOP0_helper(AND, 32, &, __VA_ARGS__)
#define INCb(...) INCDEC_helper(INC,  8, +, __VA_ARGS__)
#define INCw(...) INCDEC_helper(INC, 16, +, __VA_ARGS__)
#define INCd(...) INCDEC_helper(INC, 32, +, __VA_ARGS__)
#define DECb(...) INCDEC_helper(DEC,  8, -, __VA_ARGS__)
#define DECw(...) INCDEC_helper(DEC, 16, -, __VA_ARGS__)
#define DECd(...) INCDEC_helper(DEC, 32, -, __VA_ARGS__)
#define NOTb(a, la, sa) sa(a, ~la(a));
#define NOTw(a, la, sa) sa(a, ~la(a));
#define NOTd(a, la, sa) sa(a, ~la(a));
#define NEGb(...) NEG_helper(8,  __VA_ARGS__)
#define NEGw(...) NEG_helper(16, __VA_ARGS__)
#define NEGd(...) NEG_helper(32, __VA_ARGS__)

#define SHL_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext ## BIT(x << y); \
		cpu->cc.dst2 = cpu->cc.dst >> 31; \
		cpu->cc.op = CC_SHL; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHLb(...) SHL_helper(8, __VA_ARGS__)
#define SHLw(...) SHL_helper(16, __VA_ARGS__)
#define SHLd(a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext32(x << y); \
		cpu->cc.dst2 = x >> (sizeof(uword) * 8 - 1 - y); \
		cpu->cc.op = CC_SHL; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define ROL_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext ## BIT((x << y) | (x >> (BIT - y))); \
		cpu->cc.dst2 = cpu->cc.dst >> 31; \
		cpu->cc.op = CC_ROL; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}

#define ROLb(...) ROL_helper(8, __VA_ARGS__)
#define ROLw(...) ROL_helper(16, __VA_ARGS__)
#define ROLd(a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext32((x << y) | (x >> (32 - y))); \
		cpu->cc.dst2 = x >> (sizeof(uword) * 8 - 1 - y); \
		cpu->cc.op = CC_ROL; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}

#define RCL_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		uword cf = get_CF(cpu); \
		cpu->cc.dst = sext ## BIT((x << y) | (cf << (y - 1)) | (x >> (BIT + 1 - y))); \
		cpu->cc.dst2 = (x >> (BIT - y)) & 1; \
		cpu->cc.op = CC_RCL; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}
#define RCLb(...) RCL_helper(8, __VA_ARGS__)
#define RCLw(...) RCL_helper(16, __VA_ARGS__)
#define RCLd(...) RCL_helper(32, __VA_ARGS__)

#define RCR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		uword cf = get_CF(cpu); \
		cpu->cc.dst = sext ## BIT((x >> y) | (cf << (BIT - y)) | (x << (BIT + 1 - y))); \
		cpu->cc.dst2 = sext ## BIT(x << (BIT - y)) >> (BIT - 1); \
		cpu->cc.op = CC_RCR; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}
#define RCRb(...) RCR_helper(8, __VA_ARGS__)
#define RCRw(...) RCR_helper(16, __VA_ARGS__)
#define RCRd(...) RCR_helper(32, __VA_ARGS__)

#define ROR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext ## BIT((x >> y) | (x << (BIT - y))); \
		cpu->cc.dst2 = cpu->cc.dst >> 31; \
		cpu->cc.op = CC_ROR; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}

#define RORb(...) ROR_helper(8, __VA_ARGS__)
#define RORw(...) ROR_helper(16, __VA_ARGS__)
#define RORd(a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.dst = sext32((x >> y) | (x << (32 - y))); \
		cpu->cc.dst2 = x >> (sizeof(uword) * 8 - 1 - y); \
		cpu->cc.op = CC_ROR; \
		cpu->cc.mask = CF | PF | ZF | SF; \
		if (y == 1) cpu->cc.mask |= OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = lb(b); \
	if (y) { \
		cpu->cc.src1 = sext ## BIT(x); \
		cpu->cc.dst = sext ## BIT(x >> y); \
		cpu->cc.dst2 = (x >> (y - 1)) & 1; \
		cpu->cc.op = CC_SHR; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHRb(...) SHR_helper(8, __VA_ARGS__)
#define SHRw(...) SHR_helper(16, __VA_ARGS__)
#define SHRd(...) SHR_helper(32, __VA_ARGS__)

#define SHLD_helper(BIT, a, b, c, la, sa, lb, sb, lc, sc) \
	int count = lc(c); \
	uword x = la(a); \
	uword y = lb(b); \
	if (count) { \
		cpu->cc.src1 = sext ## BIT(x); \
		cpu->cc.dst = sext ## BIT((x << count) | (y >> (BIT - count))); \
		cpu->cc.dst2 = sext ## BIT((x << (count - 1)) | (y >> (BIT - (count - 1)))); \
		cpu->cc.op = CC_SHLD; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHLDw(...) SHLD_helper(16, __VA_ARGS__)
#define SHLDd(...) SHLD_helper(32, __VA_ARGS__)

#define SHRD_helper(BIT, a, b, c, la, sa, lb, sb, lc, sc) \
	int count = lc(c); \
	uword x = la(a); \
	uword y = lb(b); \
	if (count) { \
		cpu->cc.src1 = sext ## BIT(x); \
		cpu->cc.dst = sext ## BIT((x >> count) | (y << (BIT - count))); \
		cpu->cc.dst2 = sext ## BIT((x >> (count - 1)) | (y << (BIT - (count - 1)))); \
		cpu->cc.op = CC_SHRD; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHRDw(...) SHRD_helper(16, __VA_ARGS__)
#define SHRDd(...) SHRD_helper(32, __VA_ARGS__)

// ">>"
#define SAR_helper(BIT, a, b, la, sa, lb, sb) \
	sword x = sext ## BIT(la(a)); \
	sword y = lb(b); \
	if (y) { \
		cpu->cc.dst = x >> y; \
		cpu->cc.dst2 = (x >> (y - 1)) & 1; \
		cpu->cc.op = CC_SAR; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SARb(...) SAR_helper(8, __VA_ARGS__)
#define SARw(...) SAR_helper(16, __VA_ARGS__)
#define SARd(...) SAR_helper(32, __VA_ARGS__)

#define IMUL2_helper(BIT, a, b, la, sa, lb, sb)	\
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_IMUL ## BIT; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2w(...) IMUL2_helper(16, __VA_ARGS__)
#define IMUL2d(...) IMUL2_helper(32, __VA_ARGS__)

#define IMUL2I_helper(BIT, BITI, a, b, c, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(lb(b)); \
	cpu->cc.src2 = sext ## BITI(c); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_IMUL ## BIT; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2wIb(...) IMUL2I_helper(16, 8, __VA_ARGS__)
#define IMUL2wIw(...) IMUL2I_helper(16, 16, __VA_ARGS__)
#define IMUL2dIb(...) IMUL2I_helper(32, 8, __VA_ARGS__)
#define IMUL2dId(...) IMUL2I_helper(32, 32, __VA_ARGS__)

#define IMULb(a, la, sa) \
	cpu->cc.src1 = sext8(lreg8(0)); \
	cpu->cc.src2 = sext8(la(a)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_IMUL8; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst);

#define IMULw(a, la, sa) \
	cpu->cc.src1 = sext32(lreg16(0)); \
	cpu->cc.src2 = sext32(la(a)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_IMUL16; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst); \
	sreg16(2, (cpu->cc.dst >> 16));

#define IMULd(a, la, sa) \
	cpu->cc.src1 = sext32(lreg32(0)); \
	cpu->cc.src2 = sext32(la(a)); \
	int64_t res = (int64_t) (s32) cpu->cc.src1 * (int64_t) (s32) cpu->cc.src2; \
	cpu->cc.dst = res; \
	cpu->cc.dst2 = res >> 32; \
	cpu->cc.op = CC_IMUL32; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg32(0, cpu->cc.dst); \
	sreg32(2, cpu->cc.dst2);

#define MULb(a, la, sa) \
	cpu->cc.src1 = lreg8(0); \
	cpu->cc.src2 = la(a); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_MUL8; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst);

#define MULw(a, la, sa) \
	cpu->cc.src1 = lreg16(0); \
	cpu->cc.src2 = la(a); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.dst2 = 0; \
	cpu->cc.op = CC_MUL16; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst); \
	sreg16(2, (cpu->cc.dst >> 16));

#define MULd(a, la, sa) \
	cpu->cc.src1 = lreg32(0); \
	cpu->cc.src2 = la(a); \
	uint64_t res = (uint64_t) cpu->cc.src1 * (uint64_t) cpu->cc.src2; \
	cpu->cc.dst = res; \
	cpu->cc.dst2 = res >> 32; \
	cpu->cc.op = CC_MUL32; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg32(0, cpu->cc.dst); \
	sreg32(2, cpu->cc.dst2);

#define IDIVb(a, la, sa) \
	sword src1 = sext16(lreg16(0)); \
	sword src2 = sext8(la(a)); \
	cpu->cc.mask = 0; \
	sreg8(0, src1 / src2); \
	sreg8(4, src1 % src2);

#define IDIVw(a, la, sa) \
	sword src1 = sext32(lreg16(0) | (lreg16(2)<< 16)); \
	sword src2 = sext16(la(a)); \
	cpu->cc.mask = 0; \
	sreg16(0, src1 / src2); \
	sreg16(2, src1 % src2);

#define IDIVd(a, la, sa) \
	int64_t src1 = (((uint64_t) lreg32(2)) << 32) | lreg32(0); \
	int64_t src2 = sext32(la(a)); \
	cpu->cc.mask = 0; \
	sreg32(0, src1 / src2); \
	sreg32(2, src1 % src2);

#define DIVb(a, la, sa) \
	uword src1 = lreg16(0); \
	uword src2 = la(a); \
	cpu->cc.mask = 0; \
	sreg8(0, src1 / src2); \
	sreg8(4, src1 % src2);

#define DIVw(a, la, sa) \
	uword src1 = lreg16(0) | (lreg16(2)<< 16); \
	uword src2 = la(a); \
	cpu->cc.mask = 0; \
	sreg16(0, src1 / src2); \
	sreg16(2, src1 % src2);

#define DIVd(a, la, sa) \
	uint64_t src1 = (((uint64_t) lreg32(2)) << 32) | lreg32(0); \
	uint64_t src2 = la(a); \
	cpu->cc.mask = 0; \
	sreg32(0, src1 / src2); \
	sreg32(2, src1 % src2);

#define BT_helper(BIT, a, b, la, sa, lb, sb) \
	int bb = lb(b) % BIT; \
	bool bit = (la(a) >> bb) & 1; \
	cpu->cc.mask &= ~CF; \
	if (bit) { \
		cpu->flags |= CF; \
	} else { \
		cpu->flags &= ~CF; \
	}

#define BTw(...) BT_helper(16, __VA_ARGS__)
#define BTd(...) BT_helper(32, __VA_ARGS__)

#define BTX_helper(BIT, OP, a, b, la, sa, lb, sb) \
	int bb = lb(b) % BIT; \
	bool bit = (la(a) >> bb) & 1; \
	sa(a, la(a) OP (1 << bb)); \
	cpu->cc.mask &= ~CF; \
	if (bit) { \
		cpu->flags |= CF; \
	} else { \
		cpu->flags &= ~CF; \
	}

#define BTSw(...) BTX_helper(16, |, __VA_ARGS__)
#define BTSd(...) BTX_helper(32, |, __VA_ARGS__)
#define BTRw(...) BTX_helper(16, & ~, __VA_ARGS__)
#define BTRd(...) BTX_helper(32, & ~, __VA_ARGS__)
#define BTCw(...) BTX_helper(16, ^, __VA_ARGS__)
#define BTCd(...) BTX_helper(32, ^, __VA_ARGS__)

#define BSF_helper(BIT, a, b, la, sa, lb, sb) \
	u ## BIT src = lb(b); \
	u ## BIT temp = 0; \
	cpu->cc.mask = 0; \
	if (src == 0) { \
		cpu->flags |= ZF; \
	} else { \
		cpu->flags &= ~ZF; \
		while ((src & 1) == 0) { \
			temp++; \
			src >>= 1; \
		} \
		sa(a, temp); \
	}

#define BSFw(...) BSF_helper(16, __VA_ARGS__)
#define BSFd(...) BSF_helper(32, __VA_ARGS__)

#define BSR_helper(BIT, a, b, la, sa, lb, sb) \
	s ## BIT src = lb(b); \
	u ## BIT temp = BIT - 1; \
	cpu->cc.mask = 0; \
	if (src == 0) { \
		cpu->flags |= ZF; \
	} else { \
		cpu->flags &= ~ZF; \
		while (src >= 0) { \
			temp--; \
			src <<= 1; \
		} \
		sa(a, temp); \
	}

#define BSRw(...) BSR_helper(16, __VA_ARGS__)
#define BSRd(...) BSR_helper(32, __VA_ARGS__)

#define MOVb(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVw(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVd(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVSeg(a, b, la, sa, lb, sb) TRY(set_seg(cpu, a, lb(b)));
#define MOVZXdb(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVZXwb(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVZXww(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVZXdw(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVSXdb(a, b, la, sa, lb, sb) sa(a, sext8(lb(b)));
#define MOVSXwb(a, b, la, sa, lb, sb) sa(a, sext8(lb(b)));
#define MOVSXww(a, b, la, sa, lb, sb) sa(a, lb(b));
#define MOVSXdw(a, b, la, sa, lb, sb) sa(a, sext16(lb(b)));

#define XCHG(a, b, la, sa, lb, sb) \
	uword tmp = lb(b); \
	sb(b, la(a)); \
	sa(a, tmp);
#define XCHGb XCHG
#define XCHGw XCHG
#define XCHGd XCHG

#define XCHGAX() \
	if (opsz16) { \
		int reg = b1 & 7; \
		uword tmp = lreg16(reg); \
		sreg16(reg, lreg16(0)); \
		sreg16(0, tmp); \
	} else { \
		int reg = b1 & 7; \
		uword tmp = lreg32(reg); \
		sreg32(reg, lreg32(0)); \
		sreg32(0, tmp); \
	}

#define LEAd(a, b, la, sa, lb, sb) \
	if (mod == 3) cpu_abort(cpu, 0); \
	sa(a, b);

#define CBW_CWDE() \
	if (opsz16) sreg16(0, sext8(lreg8(0))); \
	else sreg32(0, sext16(lreg16(0)));

#define CWD_CDQ() \
	if (opsz16) sreg16(2, sext16(-(sext16(lreg16(0)) >> 15))); \
	else sreg32(2, sext32(-(sext32(lreg32(0)) >> 31)));

#define MOVFC() \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	if (reg == 0) { \
		sreg32(rm, cpu->cr0); \
	} else if (reg == 2) { \
		sreg32(rm, cpu->cr2); \
	} else if (reg == 3) { \
		sreg32(rm, cpu->cr3); \
	} else { \
		cpu->excno = EX_UD; \
		return false; \
	}

#define MOVTC() \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	if (reg == 0) { \
		u32 new_cr0 = lreg32(rm); \
		if ((new_cr0 ^ cpu->cr0) & CR0_PG) \
			tlb_clear(cpu); \
		cpu->cr0 = new_cr0; \
	} else if (reg == 2) { \
		cpu->cr2 = lreg32(rm); \
	} else if (reg == 3) { \
		cpu->cr3 = lreg32(rm); \
		tlb_clear(cpu); \
	} else { \
		cpu->excno = EX_UD; \
		return false; \
	}

#define INT3() \
	cpu->excno = EX_BP; \
	return false;

#define INTO() \
	if (get_OF(cpu)) { \
		cpu->excno = EX_OF; \
		return false; \
	}

#define INT(i, li, _) \
	cpu->excno = li(i); \
	cpu->ip = cpu->next_ip; \
	return false;

#define IRET() \
	OptAddr meml1, meml2, meml3, meml4, meml5; \
	int p0 = cpu->seg[SEG_CS].sel; \
	uword sp = lreg32(4); \
	/* ip */ TRY(translate32(cpu, &meml1, 1, SEG_SS, sp)); \
	uword newip = laddr32(&meml1); \
	/* cs */ TRY(translate32(cpu, &meml2, 1, SEG_SS, sp + 4)); \
	int p1 = laddr32(&meml2); \
	bool ptrans = (p1 & 3) != (p0 & 3); \
	/* flags */ TRY(translate32(cpu, &meml3, 1, SEG_SS, sp + 8)); \
	if (ptrans) { \
		/* sp */ TRY(translate32(cpu, &meml4, 1, SEG_SS, sp + 12)); \
		/* ss */ TRY(translate32(cpu, &meml5, 1, SEG_SS, sp + 16)); \
		uword newsp = laddr32(&meml4); \
		uword newss = laddr32(&meml5); \
		TRY(set_seg(cpu, SEG_CS, p1)); \
		TRY(set_seg(cpu, SEG_SS, newss)); \
		cpu->gpr[4] = newsp; \
		cpu->next_ip = newip; \
	} else { \
		TRY(set_seg(cpu, SEG_CS, p1)); \
		cpu->gpr[4] = sp + 12; \
		cpu->next_ip = newip; \
	} \
	cpu->flags = laddr32(&meml3); \
	cpu->flags &= 0x37fd7; \
	cpu->flags |= 0x2; \
	cpu->cc.mask = 0;

#define HLT() cpu->halt = true; return true;
#define NOP()

#define LAHF() \
	refresh_flags(cpu); \
	cpu->cc.mask = 0; \
	sreg8(4, cpu->flags);

#define SAHF() \
	cpu->cc.mask &= OF; \
	cpu->flags = cpu->flags & (wordmask ^ 0xff) | lreg8(4);

#define CMC() \
	int cf = get_CF(cpu); \
	cpu->cc.mask &= ~CF; \
	if (cf) \
		cpu->flags &= ~CF; \
	else \
		cpu->flags |= CF;

#define CLC() \
	cpu->cc.mask &= ~CF; \
	cpu->flags &= ~CF;

#define STC() \
	cpu->cc.mask &= ~CF; \
	cpu->flags |= CF;

#define CLI() \
	cpu->flags &= ~IF;

#define STI() \
	cpu->flags |= IF;

#define CLD() \
	cpu->flags &= ~DF;

#define STD() \
	cpu->flags |= DF;

#define PUSHb(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4); \
	saddr32(&meml1, sext8(la(a)));

#define PUSHw(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml1, 2, SEG_SS, sp - 2)); \
	sreg32(4, sp - 2); \
	saddr16(&meml1, sext16(la(a)));

#define PUSHd(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4); \
	saddr32(&meml1, sext32(la(a)));

#define POPRegw(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml1, 1, SEG_SS, sp)); \
	u16 src = laddr16(&meml1); \
	sreg32(4, sp + 2); \
	sa(a, src);

#define POPRegd(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp)); \
	u32 src = laddr32(&meml1); \
	sreg32(4, sp + 4); \
	sa(a, src);

#define POPw() \
	OptAddr meml1; \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml1, 1, SEG_SS, sp)); \
	u16 src = laddr16(&meml1); \
	sreg32(4, sp + 2); \
	if (mod == 3) { \
		sreg16(rm, src); \
	} else { \
		if (!modsib(cpu, mod, rm, &addr) || \
		    !translate16(cpu, &meml, 2, curr_seg, addr)) { \
			sreg32(4, sp); \
			return false; \
		} \
		saddr16(&meml, src); \
	}

#define POPd() \
	OptAddr meml1; \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp)); \
	u32 src = laddr32(&meml1); \
	sreg32(4, sp + 4); \
	if (mod == 3) { \
		sreg32(rm, src); \
	} else { \
		if (!modsib(cpu, mod, rm, &addr) || \
		    !translate32(cpu, &meml, 2, curr_seg, addr)) { \
			sreg32(4, sp); \
			return false; \
		} \
		saddr32(&meml, src); \
	}
#define POP() if (opsz16) { POPw(); } else { POPd(); }

//opsz
#define PUSHF() \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, sp - 4)); \
	refresh_flags(cpu); \
	cpu->cc.mask = 0; \
	sreg32(4, sp - 4); \
	saddr32(&meml, cpu->flags);

//opsz
#define POPF() \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 1, SEG_SS, sp)); \
	sreg32(4, sp + 4); \
	cpu->flags = laddr32(&meml); \
	cpu->flags &= /*0x37fd7*/ 0x77fd7;   \
	cpu->flags |= 0x2; \
	cpu->cc.mask = 0;

//opsz
#define PUSHSeg(seg) \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4); \
	saddr32(&meml, lseg(seg));
#define PUSH_ES() PUSHSeg(SEG_ES)
#define PUSH_CS() PUSHSeg(SEG_CS)
#define PUSH_SS() PUSHSeg(SEG_SS)
#define PUSH_DS() PUSHSeg(SEG_DS)
#define PUSH_FS() PUSHSeg(SEG_FS)
#define PUSH_GS() PUSHSeg(SEG_GS)

//opsz
#define POPSeg(seg) \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 1, SEG_SS, sp)); \
	TRY(set_seg(cpu, seg, laddr32(&meml))); \
	sreg32(4, sp + 4);
#define POP_ES() POPSeg(SEG_ES)
#define POP_SS() POPSeg(SEG_SS)
#define POP_DS() POPSeg(SEG_DS)
#define POP_FS() POPSeg(SEG_FS)
#define POP_GS() POPSeg(SEG_GS)

//opsz
#define PUSHA() \
	uword sp = lreg32(4); \
	OptAddr meml1, meml2, meml3, meml4; \
	OptAddr meml5, meml6, meml7, meml8; \
	TRY(translate32(cpu, &meml1, 2, SEG_SS, sp - 4 * 1)); \
	TRY(translate32(cpu, &meml2, 2, SEG_SS, sp - 4 * 2)); \
	TRY(translate32(cpu, &meml3, 2, SEG_SS, sp - 4 * 3)); \
	TRY(translate32(cpu, &meml4, 2, SEG_SS, sp - 4 * 4)); \
	TRY(translate32(cpu, &meml5, 2, SEG_SS, sp - 4 * 5)); \
	TRY(translate32(cpu, &meml6, 2, SEG_SS, sp - 4 * 6)); \
	TRY(translate32(cpu, &meml7, 2, SEG_SS, sp - 4 * 7)); \
	TRY(translate32(cpu, &meml8, 2, SEG_SS, sp - 4 * 8)); \
	saddr32(&meml1, lreg32(0)); \
	saddr32(&meml2, lreg32(1)); \
	saddr32(&meml3, lreg32(2)); \
	saddr32(&meml4, lreg32(3)); \
	saddr32(&meml5, sp); \
	saddr32(&meml6, lreg32(5)); \
	saddr32(&meml7, lreg32(6)); \
	saddr32(&meml8, lreg32(7)); \
	sreg32(4, sp - 4 * 8);

//opsz
#define POPA() \
	uword sp = lreg32(4); \
	OptAddr meml1, meml2, meml3, meml4; \
	OptAddr meml5, meml6, meml7; \
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp + 4 * 0)); \
	TRY(translate32(cpu, &meml2, 1, SEG_SS, sp + 4 * 1)); \
	TRY(translate32(cpu, &meml3, 1, SEG_SS, sp + 4 * 2)); \
	TRY(translate32(cpu, &meml4, 1, SEG_SS, sp + 4 * 4)); \
	TRY(translate32(cpu, &meml5, 1, SEG_SS, sp + 4 * 5)); \
	TRY(translate32(cpu, &meml6, 1, SEG_SS, sp + 4 * 6)); \
	TRY(translate32(cpu, &meml7, 1, SEG_SS, sp + 4 * 7)); \
	sreg32(7, laddr32(&meml1)); \
	sreg32(6, laddr32(&meml2)); \
	sreg32(5, laddr32(&meml3)); \
	sreg32(3, laddr32(&meml4)); \
	sreg32(2, laddr32(&meml5)); \
	sreg32(1, laddr32(&meml6)); \
	sreg32(0, laddr32(&meml7)); \
	sreg32(4, sp + 4 * 8);

// string operations
#define stdi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, REGi(7))); \
	saddr ## BIT(&meml, ax); \
	REGi(7) += dir;

#define ldsi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(6))); \
	ax = laddr ## BIT(&meml); \
	REGi(6) += dir;

#define lddi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(7))); \
	ax = laddr ## BIT(&meml); \
	REGi(7) += dir;

#define ldsistdi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(6))); \
	ax = laddr ## BIT(&meml); \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, REGi(7))); \
	saddr ## BIT(&meml, ax); \
	REGi(6) += dir; \
	REGi(7) += dir;

#define ldsilddi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(6))); \
	ax0 = laddr ## BIT(&meml); \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(7))); \
	ax = laddr ## BIT(&meml); \
	REGi(6) += dir; \
	REGi(7) += dir;

#define xdir8 int dir = (cpu->flags & DF) ? -1 : 1;
#define xdir16 int dir = (cpu->flags & DF) ? -2 : 2;
#define xdir32 int dir = (cpu->flags & DF) ? -4 : 4;

#define STOS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax = REGi(0); \
	if (rep == 0) { \
		stdi(BIT) \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		while (REGi(1)) { \
			stdi(BIT) \
			REGi(1)--; \
		} \
	}

#define LODS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		ldsi(BIT) \
		sreg ## BIT(0, ax); \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		while (REGi(1)) { \
			ldsi(BIT) \
			sreg ## BIT(0, ax); \
			REGi(1)--; \
		} \
	}

#define SCAS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax0 = REGi(0); \
	u ## BIT ax; \
	if (rep == 0) { \
		lddi(BIT) \
		cpu->cc.src1 = sext ## BIT(ax0); \
		cpu->cc.src2 = sext ## BIT(ax); \
		cpu->cc.dst = cpu->cc.src1 - cpu->cc.src2; \
		cpu->cc.op = CC_SUB; \
		cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	} else { \
		while (REGi(1)) { \
			lddi(BIT) \
			REGi(1)--; \
			cpu->cc.src1 = sext ## BIT(ax0); \
			cpu->cc.src2 = sext ## BIT(ax); \
			cpu->cc.dst = cpu->cc.src1 - cpu->cc.src2; \
			cpu->cc.op = CC_SUB; \
			cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
			bool zf = get_ZF(cpu); \
			if (zf && rep == 2 || !zf && rep == 1) break; \
		} \
	}

#define MOVS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		ldsistdi(BIT) \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		while (REGi(1)) { \
			ldsistdi(BIT) \
			REGi(1)--; \
		} \
	}

#define CMPS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax0, ax; \
	if (rep == 0) { \
		ldsilddi(BIT) \
		cpu->cc.src1 = sext ## BIT(ax0); \
		cpu->cc.src2 = sext ## BIT(ax); \
		cpu->cc.dst = cpu->cc.src1 - cpu->cc.src2; \
		cpu->cc.op = CC_SUB; \
		cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	} else { \
		while (REGi(1)) { \
			ldsilddi(BIT) \
			REGi(1)--; \
			cpu->cc.src1 = sext ## BIT(ax0); \
			cpu->cc.src2 = sext ## BIT(ax); \
			cpu->cc.dst = cpu->cc.src1 - cpu->cc.src2; \
			cpu->cc.op = CC_SUB; \
			cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
			bool zf = get_ZF(cpu); \
			if (zf && rep == 2 || !zf && rep == 1) break; \
		} \
	}

#define STOSb() STOS_helper(8)
#define LODSb() LODS_helper(8)
#define SCASb() SCAS_helper(8)
#define MOVSb() MOVS_helper(8)
#define CMPSb() CMPS_helper(8)
#define STOS() if (opsz16) { STOS_helper(16) } else { STOS_helper(32) }
#define LODS() if (opsz16) { LODS_helper(16) } else { LODS_helper(32) }
#define SCAS() if (opsz16) { SCAS_helper(16) } else { SCAS_helper(32) }
#define MOVS() if (opsz16) { MOVS_helper(16) } else { MOVS_helper(32) }
#define CMPS() if (opsz16) { CMPS_helper(16) } else { CMPS_helper(32) }

#define indxstdi(BIT) \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, REGi(7))); \
	ax = cpu->io_read ## BIT(cpu->io, lreg16(2)); \
	saddr ## BIT(&meml, ax); \
	REGi(7) += dir;

#define INS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		indxstdi(BIT) \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		while (REGi(1)) { \
			indxstdi(BIT) \
			REGi(1)--; \
		} \
	}

#define INSb() INS_helper(8)
#define INS() if (opsz16) { INS_helper(16) } else { INS_helper(32) }

#define ldsioutdx(BIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, REGi(6))); \
	ax = laddr ## BIT(&meml); \
	cpu->io_write ## BIT(cpu->io, lreg16(2), ax); \
	REGi(6) += dir;

#define OUTS_helper(BIT) \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		ldsioutdx(BIT) \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		while (REGi(1)) { \
			ldsioutdx(BIT) \
			REGi(1)--; \
		} \
	}

#define OUTSb() OUTS_helper(8)
#define OUTS() if (opsz16) { OUTS_helper(16) } else { OUTS_helper(32) }

#define JCXZb(i, li, _) \
	sword d = sext8(li(i)); \
	if (opsz16) { \
		if (lreg16(1) == 0) cpu->next_ip += d; \
	} else { \
		if (lreg32(1) == 0) cpu->next_ip += d; \
	}

#define LOOPb(i, li, _) \
	sword d = sext8(li(i)); \
	if (opsz16) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	REGi(1)--; \
	if (REGi(1)) cpu->next_ip += d;

#define LOOPEb(i, li, _) \
	sword d = sext8(li(i)); \
	if (opsz16) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	REGi(1)--; \
	if (REGi(1) && get_ZF(cpu)) cpu->next_ip += d;

#define LOOPNEb(i, li, _) \
	sword d = sext8(li(i)); \
	if (opsz16) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	REGi(1)--; \
	if (REGi(1) && !get_ZF(cpu)) cpu->next_ip += d;

/*
  70: OF=1
  71: OF=0
  72: CF=1
  73: CF=0 (above or equal)
  74: ZF=1
  75: ZF=0
  76: CF=1 || ZF=1
  77: CF=0 && ZF=0 (above)
  78: SF=1
  79: SF=0
  7a: PF=1
  7b: PF=0
  7c: SF!=OF
  7d: SF=OF
  7e: ZF=1 || SF!=OF
  7f: ZF=0 && SF =OF
 */
#define JCC_common(d) \
	int cond; \
	switch(b1 & 0xf) { \
	case 0x0: cond =  get_OF(cpu); break; \
	case 0x1: cond = !get_OF(cpu); break; \
	case 0x2: cond =  get_CF(cpu); break; \
	case 0x3: cond = !get_CF(cpu); break; \
	case 0x4: cond =  get_ZF(cpu); break; \
	case 0x5: cond = !get_ZF(cpu); break; \
	case 0x6: cond =  get_ZF(cpu) ||  get_CF(cpu); break; \
	case 0x7: cond = !get_ZF(cpu) && !get_CF(cpu); break; \
	case 0x8: cond =  get_SF(cpu); break; \
	case 0x9: cond = !get_SF(cpu); break; \
	case 0xa: cond =  get_PF(cpu); break; \
	case 0xb: cond = !get_PF(cpu); break; \
	case 0xc: cond =  get_SF(cpu) != get_OF(cpu); break; \
	case 0xd: cond =  get_SF(cpu) == get_OF(cpu); break; \
	case 0xe: cond =  get_ZF(cpu) || get_SF(cpu) != get_OF(cpu); break; \
	case 0xf: cond = !get_ZF(cpu) && get_SF(cpu) == get_OF(cpu); break; \
	} \
	if (cond) cpu->next_ip += d;

#define SETCCb(a, la, sa) \
	int cond; \
	switch(b1 & 0xf) { \
	case 0x0: cond =  get_OF(cpu); break; \
	case 0x1: cond = !get_OF(cpu); break; \
	case 0x2: cond =  get_CF(cpu); break; \
	case 0x3: cond = !get_CF(cpu); break; \
	case 0x4: cond =  get_ZF(cpu); break; \
	case 0x5: cond = !get_ZF(cpu); break; \
	case 0x6: cond =  get_ZF(cpu) ||  get_CF(cpu); break; \
	case 0x7: cond = !get_ZF(cpu) && !get_CF(cpu); break; \
	case 0x8: cond =  get_SF(cpu); break; \
	case 0x9: cond = !get_SF(cpu); break; \
	case 0xa: cond =  get_PF(cpu); break; \
	case 0xb: cond = !get_PF(cpu); break; \
	case 0xc: cond =  get_SF(cpu) != get_OF(cpu); break; \
	case 0xd: cond =  get_SF(cpu) == get_OF(cpu); break; \
	case 0xe: cond =  get_ZF(cpu) || get_SF(cpu) != get_OF(cpu); break; \
	case 0xf: cond = !get_ZF(cpu) && get_SF(cpu) == get_OF(cpu); break; \
	} \
	sa(a, cond);

#define JCCb(i, li, _) \
	sword d = sext8(li(i)); \
	JCC_common(d)

#define JCCd(i, li, _) \
	sword d = sext32(li(i)); \
	JCC_common(d)

#define JMPb(i, li, _) \
	sword d = sext8(li(i)); \
	cpu->next_ip += d;

#define JMPd(i, li, _) \
	sword d = sext32(li(i)); \
	cpu->next_ip += d;

#define JMPABSw(i, li, _) \
	cpu->excno = EX_UD; \
	return false;

#define JMPABSd(i, li, _) \
	cpu->next_ip = li(i);

#define JMPFAR() \
	u32 newip; \
	u16 newseg; \
	TRY(fetch32(cpu, &newip)); \
	TRY(fetch16(cpu, &newseg)); \
	TRY(set_seg(cpu, SEG_CS, newseg)); \
	cpu->next_ip = newip;

#define CALLd(i, li, _) \
	sword d = sext32(li(i)); \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4); \
	saddr32(&meml, cpu->next_ip); \
	cpu->next_ip += d;

#define CALLABSw(i, li, _) \
	cpu->excno = EX_UD; \
	return false;

#define CALLABSd(i, li, _) \
	uword nip = li(i); \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4); \
	saddr32(&meml, cpu->next_ip); \
	cpu->next_ip = nip;

// opsz
#define RETw(i, li, _) \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 1, SEG_SS, sp)); \
	sreg32(4, sp + 4 + li(i)); \
	cpu->next_ip = laddr32(&meml);

// opsz
#define RET() \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 1, SEG_SS, sp)); \
	sreg32(4, sp + 4); \
	cpu->next_ip = laddr32(&meml);

// opsz
#define ENTER(i16, i8, l16, s16, l8, s8) \
	OptAddr meml1; \
	int level = l8(i8); \
	if (level != 0) cpu_abort(cpu, -1); \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 2, SEG_SS, sp - 4)); \
	sreg32(4, sp - 4 - l16(i16)); \
	saddr32(&meml1, lreg32(5));

// opsz
#define LEAVE() \
	uword sp = lreg32(5); \
	TRY(translate32(cpu, &meml, 1, SEG_SS, sp)); \
	sreg32(4, sp + 4); \
	sreg32(5, laddr32(&meml));

#define SGDT(addr) \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 2, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 2, curr_seg, addr + 2)); \
	store16(cpu, &meml1, cpu->gdt.limit); \
	store32(cpu, &meml2, cpu->gdt.base);

#define SIDT(addr) \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 2, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 2, curr_seg, addr + 2)); \
	store16(cpu, &meml1, cpu->idt.limit); \
	store32(cpu, &meml2, cpu->idt.base);

#define LGDT(addr) \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 1, curr_seg, addr + 2)); \
	u16 limit = load16(cpu, &meml1); \
	u32 base = load32(cpu, &meml2); \
	cpu->gdt.base = base; \
	cpu->gdt.limit = limit;

#define LIDT(addr) \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 1, curr_seg, addr + 2)); \
	u16 limit = load16(cpu, &meml1); \
	u32 base = load32(cpu, &meml2); \
	cpu->idt.base = base; \
	cpu->idt.limit = limit;

//TODO
#define LLDT(a, la, sa) \
	TRY(set_seg(cpu, SEG_LDT, la(a)));

#define LTR(a, la, sa) \
	TRY(set_seg(cpu, SEG_TR, la(a)));

#define MOVFD() \
	TRY(fetch8(cpu, &modrm));
#define MOVTD() \
	TRY(fetch8(cpu, &modrm));
#define MOVFT() \
	TRY(fetch8(cpu, &modrm));
#define MOVTT() \
	TRY(fetch8(cpu, &modrm));

#define SMSW(addr, laddr, saddr) \
	saddr(addr, cpu->cr0 & 0xffff);

#define LMSW(addr, laddr, saddr) \
	cpu->cr0 = (cpu->cr0 & (~0xf)) | (laddr(addr) & 0xf);

#define LESd(reg, addr, lreg32, sreg32, laddr32, saddr32) \
	cpu->excno = EX_UD; \
	return false;

//TODO SEG opsz
#define LSSd(reg, addr, lreg32, sreg32, laddr32, saddr32) \
	OptAddr meml1, meml2; \
	TRY(translate32(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate16(cpu, &meml2, 1, curr_seg, addr + 4)); \
	u32 r = load32(cpu, &meml1); \
	u32 s = load16(cpu, &meml2); \
	TRY(set_seg(cpu, SEG_SS, s)); \
	sreg32(reg, r);

#define LDSd(reg, addr, lreg32, sreg32, laddr32, saddr32) \
	cpu->excno = EX_UD; \
	return false;

#define LFSd(reg, addr, lreg32, sreg32, laddr32, saddr32) \
	cpu->excno = EX_UD; \
	return false;

#define LGSd(reg, addr, lreg32, sreg32, laddr32, saddr32) \
	cpu->excno = EX_UD; \
	return false;

#define INb(a, b, la, sa, lb, sb) \
	sa(a, cpu->io_read8(cpu->io, lb(b)));

#define INw(a, b, la, sa, lb, sb) \
	sa(a, cpu->io_read16(cpu->io, lb(b)));

#define INd(a, b, la, sa, lb, sb) \
	sa(a, cpu->io_read32(cpu->io, lb(b)));

#define OUTb(a, b, la, sa, lb, sb) \
	cpu->io_write8(cpu->io, la(a), lb(b));

#define OUTw(a, b, la, sa, lb, sb) \
	cpu->io_write16(cpu->io, la(a), lb(b));

#define OUTd(a, b, la, sa, lb, sb) \
	cpu->io_write32(cpu->io, la(a), lb(b));

#define CLTS() \
	cpu->cr0 &= ~(1 << 3);

#define ESC() \
	if (cpu->cr0 & 0xc) { \
		cpu->excno = EX_NM; \
		return false; \
	} else { \
		TRY(fetch8(cpu, &b1)); \
	}

#define WAIT()

// 486...
#define CMPXCH_helper(BIT, a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lreg ## BIT(0)); \
	cpu->cc.dst = cpu->cc.src1 - cpu->cc.src2; \
	cpu->cc.op = CC_SUB; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	if (cpu->cc.dst == 0) sa(a, lb(b)); else sreg ## BIT(0, cpu->cc.src1); 

#define XADD_helper(BIT, a, b, la, sa, lb, sb) \
	u ## BIT dst = la(a); \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = cpu->cc.src1 + cpu->cc.src2; \
	cpu->cc.op = CC_ADD; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sb(b, dst); \
	sa(a, cpu->cc.dst);

#define CMPXCHb(...) CMPXCH_helper(8, __VA_ARGS__)
#define CMPXCHw(...) CMPXCH_helper(16, __VA_ARGS__)
#define CMPXCHd(...) CMPXCH_helper(32, __VA_ARGS__)
#define XADDb(...) XADD_helper(8, __VA_ARGS__)
#define XADDw(...) XADD_helper(16, __VA_ARGS__)
#define XADDd(...) XADD_helper(32, __VA_ARGS__)

#define INVLPG(addr) tlb_clear(cpu);

#define BSWAPw(a, la, sa) \
	cpu->excno = EX_UD; \
	return false;

#define BSWAPd(a, la, sa) \
	u32 src = la(a); \
	u32 dst = ((src & 0xff) << 24) | (((src >> 8) & 0xff) << 16) | (((src >> 16) & 0xff) << 8) | ((src >> 24) & 0xff); \
	sa(a, dst);

static bool verbose;
static bool cpu_exec1(CPUI386 *cpu, int stepcount)
{
#if 0
#define dispatch \
	if (stepcount <= 0) return true; \
	stepcount--; \
	TRY(fetch8(cpu, &b1)); \
	cpu->cycle++; goto *disp[b1];
#define eswitch(b)
#define ecase(a)   L_ ## a
#define ebreak     dispatch
#define edefault   L_default

	static void *disp[256] = {
	[0 ... 255] = &&L_default,
#define CX(_1) [_1] = &&L_##_1,
#undef I
#define I(_case, _rm, _rwm, _op) _case
#include "i386ins.def"
	CX(0x80)
	CX(0x81)
	CX(0x83)
	CX(0xc0)
	CX(0xc1)
	CX(0xd0)
	CX(0xd1)
	CX(0xd2)
	CX(0xd3)
	CX(0xf6)
	CX(0xf7)
	CX(0xfe)
	CX(0xff)
	CX(0x0f)
#undef CX
#define CX(_1) L_##_1:
	};
#else
#define dispatch cpu->ip = cpu->next_ip; TRY(fetch8(cpu, &b1)); cpu->cycle++;
#define eswitch(b) switch(b)
#define ecase(a)   case a
#define ebreak     break
#define edefault   default
#undef CX
#define CX(_1) case _1:
#endif
	u8 b1;
	u8 modrm;
	OptAddr meml;
	uword addr;
	for (; stepcount > 0; stepcount--) {
	dispatch;
	if (verbose)
		cpu_debug(cpu);

	// prefix
	bool opsz16 = false;
	int rep = 0;
	bool lock = false;
	int curr_seg = SEG_DS;
	for (;;) {
		if (b1 == 0x26) {
			curr_seg = SEG_ES;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x2e) {
			curr_seg = SEG_CS;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x36) {
			curr_seg = SEG_SS;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x3e) {
			curr_seg = SEG_DS;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x64) {
			curr_seg = SEG_FS;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x65) {
			curr_seg = SEG_GS;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0x66) {
			opsz16 = true;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0xf3) { // REP
			rep = 1;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0xf2) { // REPNE
			rep = 2;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		if (b1 == 0xf0) { // LOCK
			lock = true;
			TRY(fetch8(cpu, &b1));
			continue;
		}
		break;
	}

	eswitch(b1) {
#undef I
#define I(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef I
#define I(...)
#undef CX
#define CX(_1) case _1:

	ecase(0x80): { // G1b
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG1b
#define IG1b(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG1b
#define IG1b(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0x81): { // G1v
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG1v
#define IG1v(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG1v
#define IG1v(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0x83): { // G1vIb
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG1vIb
#define IG1vIb(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG1vIb
#define IG1vIb(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xc0): { // G2b
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2b
#define IG2b(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2b
#define IG2b(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xc1): { // G2v
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2v
#define IG2v(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2v
#define IG2v(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xd0): { // G2b1
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2b1
#define IG2b1(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2b1
#define IG2b1(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xd1): { // G2v1
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2v1
#define IG2v1(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2v1
#define IG2v1(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xd2): { // G2bC
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2bC
#define IG2bC(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2bC
#define IG2bC(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xd3): { // G2v1
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG2vC
#define IG2vC(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG2vC
#define IG2vC(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xf6): { // G3b
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG3b
#define IG3b(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG3b
#define IG3b(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xf7): { // G3v
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG3v
#define IG3v(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG3v
#define IG3v(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xfe): { // G4
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG4
#define IG4(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG4
#define IG4(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0xff): { // G5
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG5
#define IG5(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG5
#define IG5(...)
		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	ecase(0x0f): { // two byte
		TRY(fetch8(cpu, &b1));
		switch(b1) {
#undef I2
#define I2(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef I2
#define I2(...)

		case 0x00: { // G6
			TRY(peek8(cpu, &modrm));
			switch((modrm >> 3) & 7) {
#undef IG6
#define IG6(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG6
#define IG6(...)
			default:
				cpu_abort(cpu, b1);
			}
			ebreak;
		}

		case 0x01: { // G7
			TRY(peek8(cpu, &modrm));
			switch((modrm >> 3) & 7) {
#undef IG7
#define IG7(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG7
#define IG7(...)
			default:
				cpu_abort(cpu, b1);
			}
			ebreak;
		}

		case 0xba: { // G8
			TRY(peek8(cpu, &modrm));
			switch((modrm >> 3) & 7) {
#undef IG8
#define IG8(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG8
#define IG8(...)
			default:
				cpu_abort(cpu, b1);
			}
			ebreak;
		}

		default:
			cpu_abort(cpu, b1);
		}
		ebreak;
	}

	edefault:
		cpu_abort(cpu, b1);
	}
	}
	return true;
}

static bool ex_push_helper1(CPUI386 *cpu, uword oldss, uword oldsp, bool pusherr)
{
	OptAddr meml1, meml2, meml3, meml4, meml5, meml6;
	uword sp = lreg32(4);
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp - 4 * 1));
	TRY(translate32(cpu, &meml2, 1, SEG_SS, sp - 4 * 2));
	TRY(translate32(cpu, &meml3, 1, SEG_SS, sp - 4 * 3));
	TRY(translate32(cpu, &meml4, 1, SEG_SS, sp - 4 * 4));
	TRY(translate32(cpu, &meml5, 1, SEG_SS, sp - 4 * 5));
	if (pusherr) {
		TRY(translate32(cpu, &meml6, 1, SEG_SS, sp - 4 * 6));
	}
	saddr32(&meml1, oldss);
	saddr32(&meml2, oldsp);

	refresh_flags(cpu);
	cpu->cc.mask = 0;
	saddr32(&meml3, cpu->flags);

	saddr32(&meml4, cpu->seg[SEG_CS].sel);
	saddr32(&meml5, cpu->ip);
	if (pusherr) {
		saddr32(&meml6, cpu->excerr);
		sreg32(4, sp - 4 * 6);
	} else {
		sreg32(4, sp - 4 * 5);
	}
	return true;
}

static bool ex_push_helper2(CPUI386 *cpu, bool pusherr)
{
	OptAddr meml1, meml2, meml3, meml4;
	uword sp = lreg32(4);
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp - 4 * 1));
	TRY(translate32(cpu, &meml2, 1, SEG_SS, sp - 4 * 2));
	TRY(translate32(cpu, &meml3, 1, SEG_SS, sp - 4 * 3));
	if (pusherr) {
		TRY(translate32(cpu, &meml4, 1, SEG_SS, sp - 4 * 4));
	}

	refresh_flags(cpu);
	cpu->cc.mask = 0;
	saddr32(&meml1, cpu->flags);

	saddr32(&meml2, cpu->seg[SEG_CS].sel);
	saddr32(&meml3, cpu->ip);
	if (pusherr) {
		saddr32(&meml4, cpu->excerr);
		sreg32(4, sp - 4 * 4);
	} else {
		sreg32(4, sp - 4 * 3);
	}
	return true;
}

static bool ex_push_helper(CPUI386 *cpu, int newpl, bool pusherr)
{
	OptAddr meml;
	OptAddr msp0, mss0;

	if (newpl != (cpu->seg[SEG_CS].sel & 3)) {
		uword oldss = cpu->seg[SEG_SS].sel;
		uword oldsp = cpu->gpr[4];
		TRY(translate32(cpu, &msp0, 1, SEG_TR, 4 + 8 * newpl));
		TRY(translate32(cpu, &mss0, 1, SEG_TR, 8 + 8 * newpl));
		uword spbak = cpu->gpr[4];
		uword ssbak = cpu->seg[SEG_SS].sel;
		cpu->gpr[4] = load32(cpu, &msp0);
		TRY(set_seg(cpu, SEG_SS, load32(cpu, &mss0)));

		if (!ex_push_helper1(cpu, oldss, oldsp, pusherr)) {
			abort();
			cpu->gpr[4] = spbak;
			set_seg(cpu, SEG_SS, ssbak);
			return false;
		}
		return true;
	} else {
		return ex_push_helper2(cpu, pusherr);
	}
}

void call_isr(CPUI386 *cpu, int no, bool pusherr)
{
	OptAddr meml;
	uword base = cpu->idt.base;
	int off = no * 8;
	if (!translate_slow(cpu, &meml, 1, base + off, 4)) {
		cpu_abort(cpu, -100);
	}
	uword w1 = load32(cpu, &meml);
	if (!translate_slow(cpu, &meml, 1, base + off + 4, 4)) {
		cpu_abort(cpu, -101);
	}
	uword w2 = load32(cpu, &meml);
	int newcs = w1 >> 16;
	uword newip = (w1 & 0xffff) | (w2 & 0xffff0000);
	int gt = (w2 >> 8) & 0xf;

	if (!ex_push_helper(cpu, newcs & 3, pusherr)) {
		cpu_abort(cpu, -102);
	}

	if (!set_seg(cpu, SEG_CS, newcs)) {
		cpu_abort(cpu, -103);
	}
	cpu->next_ip = newip;
	cpu->ip = newip;
	if (gt == 0x6 || gt == 0xe)
		cpu->flags &= ~IF;
}

void cpu_step(CPUI386 *cpu, int stepcount)
{
	if ((cpu->flags & IF) && cpu->intr) {
		cpu->intr = false;
		cpu->halt = false;
		int no = cpu->pic_read_irq(cpu->pic);
		cpu->ip = cpu->next_ip;
		call_isr(cpu, no, false);
	}

	if (cpu->halt) {
		usleep(1);
		return;
	}

	if (!cpu_exec1(cpu, stepcount)) {
		bool pusherr = false;
		switch (cpu->excno) {
		case EX_DF: case EX_TS: case EX_NP: case EX_SS: case EX_GP:
		case EX_PF: case 15: case 16:
			pusherr = true;
		}
		cpu->next_ip = cpu->ip;
		call_isr(cpu, cpu->excno, pusherr);
	}
}

CPUI386 *cpu386_new(char *phys_mem, long phys_mem_size)
{
	CPUI386 *cpu = malloc(sizeof(CPUI386));
	for (int i = 0; i < 8; i++) {
		cpu->gpr[i] = 0;
	}
	cpu->ip = 0;
	cpu->next_ip = cpu->ip;
	cpu->flags = 0x2;
	cpu->halt = false;

	for (int i = 0; i < 8; i++) {
		cpu->seg[i].sel = 0;
		cpu->seg[i].base = 0;
		cpu->seg[i].limit = 0;
		cpu->seg[i].flags = 0;
	}
	cpu->seg[2].flags = (1 << 22);
	cpu->seg[1].flags = (1 << 22);

	cpu->idt.base = 0;
	cpu->idt.limit = 0x3ff;
	cpu->gdt.base = 0;
	cpu->gdt.limit = 0;

	cpu->cr0 = (1 << 0);
	cpu->cr2 = 0;
	cpu->cr3 = 0;

	cpu->cc.mask = 0;

	cpu->tlb.size = tlb_size;
	cpu->tlb.tab = malloc(sizeof(struct tlb_entry) * tlb_size);
	tlb_clear(cpu);

	cpu->phys_mem = phys_mem;
	cpu->phys_mem_size = phys_mem_size;

	cpu->cycle = 0;

	cpu->ifetch.lpgno = -1;

	cpu->intr = false;
	cpu->pic = NULL;
	cpu->pic_read_irq = NULL;

	cpu->io = NULL;
	cpu->io_read8 = NULL;
	cpu->io_write8 = NULL;
	cpu->io_read16 = NULL;
	cpu->io_write16 = NULL;
	cpu->io_read32 = NULL;
	cpu->io_write32 = NULL;
	return cpu;
}

#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
static uint32_t get_uticks()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint32_t) ts.tv_sec * 1000000 +
	    (uint32_t) ts.tv_nsec / 1000);
}

/* sysprog21/semu */
typedef struct {
	u8 dll, dlh;
	u8 lcr;
	u8 ier;
	u8 mcr;
	u8 ioready;
	int out_fd;
	u8 in;
} U8250;

U8250 *u8250_init()
{
	U8250 *s = malloc(sizeof(U8250));
	memset(s, 0, sizeof(U8250));
	s->out_fd = 1;
	return s;
}

typedef struct {
	u8 data[128];
	int index;
} CMOS;

static int bin2bcd(int a)
{
	return ((a / 10) << 4) | (a % 10);
}

CMOS *cmos_init()
{
	CMOS *c = malloc(sizeof(CMOS));
	memset(c, 0, sizeof(CMOS));

	struct tm tm;
	time_t ti;

	ti = time(NULL);
	gmtime_r(&ti, &tm);
	c->data[0] = bin2bcd(tm.tm_sec);
	c->data[2] = bin2bcd(tm.tm_min);
	c->data[4] = bin2bcd(tm.tm_hour);
	c->data[6] = bin2bcd(tm.tm_wday);
	c->data[7] = bin2bcd(tm.tm_mday);
	c->data[8] = bin2bcd(tm.tm_mon + 1);
	c->data[9] = bin2bcd(tm.tm_year % 100);
	c->data[0x32] = bin2bcd((tm.tm_year / 100) + 19);
	c->data[10] = 0x26;
	c->data[11] = 0x02;
	c->data[12] = 0x00;
	c->data[13] = 0x80;
	return c;
}

typedef struct {
	CPUI386 *cpu;
	PicState2 *pic;
	PITState *pit;
	U8250 *serial;
	CMOS *cmos;
	struct ide_controller *ide;
	char *phys_mem;
	long phys_mem_size;
	int64_t boot_start_time;
} PC;

void u8250_update_interrupts(PC *pc, U8250 *uart)
{
	if (uart->ier & uart->ioready) {
		i8259_set_irq(pc->pic, 4, 1);
	} else {
		i8259_set_irq(pc->pic, 4, 0);
	}
}

static u8 u8250_reg_read(PC *pc, U8250 *uart, int off)
{
	u8 val;
	switch (off) {
	case 0:
		if (uart->lcr & (1 << 7)) { /* DLAB */
			val = uart->dll;
			break;
		}
		val = uart->in;
		uart->ioready &= ~1;
		u8250_update_interrupts(pc, uart);
		break;
	case 1:
		if (uart->lcr & (1 << 7)) { /* DLAB */
			val = uart->dlh;
			break;
		}
		val = uart->ier;
		break;
	case 2:
		val = (uart->ier & uart->ioready) ? 0 : 1;
		break;
	case 3:
		val = uart->lcr;
		break;
	case 4:
		val = uart->mcr;
		break;
	case 5:
		/* LSR = no error, TX done & ready */
		val = 0x60 | (uart->ioready & 1);
		break;
	case 6:
		/* MSR = carrier detect, no ring, data ready, clear to send. */
		val = 0xb0;
		break;
		/* no scratch register, so we should be detected as a plain 8250. */
	default:
		val = 0;
	}
	return val;
}

static void u8250_reg_write(PC *pc, U8250 *uart, int off, u8 val)
{
	switch (off) {
	case 0:
		if (uart->lcr & (1 << 7)) {
			uart->dll = val;
			break;
		} else {
			ssize_t r;
			do {
				r = write(uart->out_fd, &val, 1);
			} while (r == -1 && errno == EINTR);
		}
		break;
	case 1:
		if (uart->lcr & (1 << 7)) {
			uart->dlh = val;
			break;
		} else {
			uart->ier = val;
			if (uart->ier & 2)
				uart->ioready |= 2;
			else
				uart->ioready &= ~2;
			u8250_update_interrupts(pc, uart);
		}
		break;
	case 3:
		uart->lcr = val;
		break;
	case 4:
		uart->mcr = val;
		break;
	}
}

static u8 cmos_ioport_read(CMOS *cmos, int addr)
{
	if (addr == 0x70)
		return 0xff;
	u8 val = cmos->data[cmos->index];
	return val;
}

static void cmos_ioport_write(CMOS *cmos, int addr, u8 val)
{
	if (addr == 0x70)
		cmos->index = val & 0x7f;
}

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
		val = u8250_reg_read(pc, pc->serial, addr - 0x3f8);
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
		val = ide_read8(pc->ide, addr - 0x1f0);
		return val;
	case 0x3f6:
		val = ide_read8(pc->ide, 8);
		return val;
	default:
		fprintf(stderr, "in 0x%x <= 0x%x\n", addr, 0);
		return 0;
	}
}

u16 pc_io_read16(void *o, int addr)
{
	PC *pc = o;
	u16 val;

	switch(addr) {
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		val = ide_read16(pc->ide, addr - 0x1f0);
		return val;
	default:
		fprintf(stderr, "inw 0x%x <= 0x%x\n", addr, 0);
		return 0;
	}
}

u32 pc_io_read32(void *o, int addr)
{
	PC *pc = o;
	if (addr == 0x3cc)
		return (get_uticks() - pc->boot_start_time) / 1000;
	fprintf(stderr, "ind 0x%x <= 0x%x\n", addr, 0);
	return 0;
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
		u8250_reg_write(pc, pc->serial, addr - 0x3f8, val);
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
		ide_write8(pc->ide, addr - 0x1f0, val);
		return;
	case 0x3f6:
		ide_write8(pc->ide, 8, val);
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
	case 0x1f0: case 0x1f1: case 0x1f2: case 0x1f3:
	case 0x1f4: case 0x1f5: case 0x1f6: case 0x1f7:
		ide_write16(pc->ide, addr - 0x1f0, val);
		return;
	default:
		fprintf(stderr, "outw 0x%x => 0x%x\n", val, addr);
		return;
	}
}

void pc_io_write32(void *o, int addr, u32 val)
{
	fprintf(stderr, "outd 0x%x => 0x%x\n", val, addr);
}

static void CtrlC()
{
	exit( 0 );
}

static void ResetKeyboardInput()
{
	// Re-enable echo, etc. on keyboard.
	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag |= ICANON | ECHO;
	tcsetattr(0, TCSANOW, &term);
}

// Override keyboard, so we can capture all keyboard input for the VM.
static void CaptureKeyboardInput()
{
	// Hook exit, because we want to re-enable keyboard.
	atexit(ResetKeyboardInput);
	signal(SIGINT, CtrlC);

	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag &= ~(ICANON | ECHO | ISIG); // Disable echo as well
	tcsetattr(0, TCSANOW, &term);
}

static int ReadKBByte()
{
	char rxchar = 0;
	int rread = read(fileno(stdin), (char*)&rxchar, 1);
	if( rread > 0 ) // Tricky: getchar can't be used with arrow keys.
		return rxchar;
	else
		abort();
}

static int IsKBHit()
{
	int byteswaiting;
	ioctl(0, FIONREAD, &byteswaiting);
	return !!byteswaiting;
}

void pc_step(PC *pc)
{
	i8254_update_irq(pc->pit);
	if (IsKBHit()) {
		if (!(pc->serial->ioready & 1)) {
			pc->serial->in = ReadKBByte();
			pc->serial->ioready |= 1;
			u8250_update_interrupts(pc, pc->serial);
		}
	}
	cpu_step(pc->cpu, 16384);
}

static void raise_irq(void *o, PicState2 *s)
{
	CPUI386 *cpu = o;
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

PC *pc_new()
{
	PC *pc = malloc(sizeof(PC));
	long mem_size = 8 * 1024 * 1024;
	char *mem = malloc(mem_size);
	memset(mem, 0, mem_size);
	pc->cpu = cpu386_new(mem, mem_size);

	pc->pic = i8259_init(raise_irq, pc->cpu);
	pc->cpu->pic = pc->pic;
	pc->cpu->pic_read_irq = read_irq;

	pc->pit = i8254_init(0, pc->pic, set_irq);
	pc->serial = u8250_init();
	pc->cmos = cmos_init();
	pc->ide = ide_allocate("ide", 14, pc->pic, set_irq);
	int idefd = open("disk20mb", O_RDWR);
	if (idefd >= 0) {
		int ret = ide_attach(pc->ide, 0, idefd);
		assert(ret == 0);
		ide_reset_begin(pc->ide);
	}
	pc->phys_mem = mem;
	pc->phys_mem_size = mem_size;

	pc->cpu->io = pc;
	pc->cpu->io_read8 = pc_io_read;
	pc->cpu->io_write8 = pc_io_write;
	pc->cpu->io_read16 = pc_io_read16;
	pc->cpu->io_write16 = pc_io_write16;
	pc->cpu->io_read32 = pc_io_read32;
	pc->cpu->io_write32 = pc_io_write32;

	pc->boot_start_time = 0;
	return pc;
}

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

int main(int argc, char *argv[])
{
	const char *vmlinux = "vmlinux.bin";
	if (argc > 1)
		vmlinux = argv[1];

	PC *pc = pc_new();

	load(pc, "linuxstart.bin", 0x0010000);
	load(pc, vmlinux, 0x00100000);
	int initrd_size = load(pc, "root.bin", 0x00400000);

	uword start_addr = 0x10000;
	uword cmdline_addr = 0xf800;
	strcpy(pc->cpu->phys_mem + cmdline_addr,
	       "console=ttyS0 root=/dev/ram0 rw init=/sbin/init notsc=1");

	pc->cpu->next_ip = start_addr;
	pc->cpu->gpr[0] = pc->phys_mem_size;
	pc->cpu->gpr[3] = initrd_size;
	pc->cpu->gpr[1] = cmdline_addr;

	CaptureKeyboardInput();

	pc->boot_start_time = get_uticks();
	for (;;) {
		pc_step(pc);
	}
	return 0;
}

void cpu_debug(CPUI386 *cpu)
{
	fprintf(stderr, "IP %08x|AX %08x|CX %08x|DX %08x|BX %08x|SP %08x|BP %08x|SI %08x|DI %08x|FL %08x|CS %04x|DS %04x|SS %04x\n",
		cpu->ip, cpu->gpr[0], cpu->gpr[1], cpu->gpr[2], cpu->gpr[3],
		cpu->gpr[4], cpu->gpr[5], cpu->gpr[6], cpu->gpr[7], cpu->flags, SEGi(SEG_CS), SEGi(SEG_DS), SEGi(SEG_SS));

	fprintf(stderr, "code: ");
	for (int i = 0; i < 16; i++) {
		OptAddr res;
		if(translate8(cpu, &res, 1, SEG_CS, cpu->ip + i))
			fprintf(stderr, " %02x", load8(cpu, &res));
		else
			fprintf(stderr, " ??");
	}
	fprintf(stderr, "\n");
}
