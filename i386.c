#include "i386.h"
#include "fpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#define wordmask ((uword) ((sword) -1))
#define TRY(f) if(!(f)) { return false; }
#define TRY1(f) if(!(f)) { fprintf(stderr, "@ %s %s %d\n", __FILE__, __FUNCTION__, __LINE__); cpu_abort(cpu, -1); }

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

enum {
	SEG_D_BIT = 1 << 14,
	SEG_B_BIT = 1 << 14,
};

#define REGi(x) (cpu->gpr[x])
#define SEGi(x) (cpu->seg[x].sel)

static void cpu_debug(CPUI386 *cpu);

void cpu_abort(CPUI386 *cpu, int code)
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

/* lazy flags */
enum {
	CC_ADC, CC_ADD,	CC_SBB, CC_SUB,
	CC_NEG8, CC_NEG16, CC_NEG32,
	CC_DEC8, CC_DEC16, CC_DEC32,
	CC_INC8, CC_INC16, CC_INC32,
	CC_IMUL8, CC_IMUL16, CC_IMUL32,	CC_MUL8, CC_MUL16, CC_MUL32,
	CC_SAR, CC_SHL, CC_SHR,
	CC_SHLD, CC_SHRD, CC_BSF, CC_BSR,
	CC_AND, CC_OR, CC_XOR,
};

static int get_CF(CPUI386 *cpu)
{
	if (cpu->cc.mask & CF) {
		switch(cpu->cc.op) {
		case CC_ADC:
			return cpu->cc.dst <= cpu->cc.src2;
		case CC_ADD:
			return cpu->cc.dst < cpu->cc.src2;
		case CC_SBB:
			return cpu->cc.src1 <= cpu->cc.src2;
		case CC_SUB:
			return cpu->cc.src1 < cpu->cc.src2;
		case CC_NEG8: case CC_NEG16: case CC_NEG32:
			return cpu->cc.dst != 0;
		case CC_DEC8: case CC_DEC16: case CC_DEC32:
		case CC_INC8: case CC_INC16: case CC_INC32:
			abort(); // should not happen
		case CC_IMUL8:
			return sext8(cpu->cc.dst) != cpu->cc.dst;
		case CC_IMUL16:
			return sext16(cpu->cc.dst) != cpu->cc.dst;
		case CC_IMUL32:
			return (((s32) cpu->cc.dst) >> 31) != cpu->cc.dst2;
		case CC_MUL8:
			return (cpu->cc.dst >> 8) != 0;
		case CC_MUL16:
			return (cpu->cc.dst >> 16) != 0;
		case CC_MUL32:
			return (cpu->cc.dst2) != 0;
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
		case CC_ADC:
		case CC_ADD:
		case CC_SBB:
		case CC_SUB:
			return ((cpu->cc.src1 ^ cpu->cc.src2 ^ cpu->cc.dst) >> 4) & 1;
		case CC_NEG8: case CC_NEG16: case CC_NEG32:
			return (cpu->cc.dst & 0xf) != 0;
		case CC_DEC8: case CC_DEC16: case CC_DEC32:
			return (cpu->cc.dst & 0xf) == 0xf;
		case CC_INC8: case CC_INC16: case CC_INC32:
			return (cpu->cc.dst & 0xf) == 0;
		case CC_IMUL8: case CC_IMUL16: case CC_IMUL32:
		case CC_MUL8: case CC_MUL16: case CC_MUL32:
			return 0;
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
		case CC_ADC:
		case CC_ADD:
			return (~(cpu->cc.src1 ^ cpu->cc.src2) & (cpu->cc.dst ^ cpu->cc.src2)) >> (sizeof(uword) * 8 - 1);
		case CC_SBB:
		case CC_SUB:
			return ((cpu->cc.src1 ^ cpu->cc.src2) & (cpu->cc.dst ^ cpu->cc.src1)) >> (sizeof(uword) * 8 - 1);
		case CC_DEC8:
			return cpu->cc.dst == sext8((u8) ~(1u << 7));
		case CC_DEC16:
			return cpu->cc.dst == sext16((u16) ~(1u << 15));
		case CC_DEC32:
			return cpu->cc.dst == sext32((u32) ~(1u << 31));
		case CC_INC8: case CC_NEG8:
			return cpu->cc.dst == sext8(1u << 7);
		case CC_INC16: case CC_NEG16:
			return cpu->cc.dst == sext16(1u << 15);
		case CC_INC32: case CC_NEG32:
			return cpu->cc.dst == sext32(1u << 31);
		case CC_IMUL8: case CC_IMUL16: case CC_IMUL32:
		case CC_MUL8: case CC_MUL16: case CC_MUL32:
			return get_CF(cpu);
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

static int get_IOPL(CPUI386 *cpu)
{
	return (cpu->flags & IOPL) >> 12;
}

/* MMU */
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
	mem[base_addr + i * 4] |= 1 << 5; // accessed

	uword base_addr2 = pde & ~0xfff;
	uword pte = mem[base_addr2 + j * 4] |
		(mem[base_addr2 + j * 4 + 1] << 8) |
		(mem[base_addr2 + j * 4 + 2] << 16) |
		(mem[base_addr2 + j * 4 + 3] << 24);
	if (!(pte & 1))
		return false;
	mem[base_addr2 + j * 4] |= 1 << 5; // accessed
//	mem[base_addr2 + j * 4] |= 1 << 6; // dirty

	ent->lpgno = lpgno;
	ent->pte = pte & ((pde & 7) | 0xfffffff8);
	ent->ppte = &(mem[base_addr2 + j * 4]);
	return true;
}

static bool translate_lpgno(CPUI386 *cpu, int rwm, uword lpgno, uword laddr, int cpl, uword *paddr)
{
	struct tlb_entry *ent = &(cpu->tlb.tab[lpgno % tlb_size]);
	if (ent->lpgno != lpgno) {
		if (!tlb_refill(cpu, ent, lpgno)) {
			cpu->cr2 = laddr;
			cpu->excno = EX_PF;
			cpu->excerr = 0;
			if (rwm & 2)
				cpu->excerr |= 2;
			if (cpl)
				cpu->excerr |= 4;
			return false;
		}
	}
	if ((rwm & 2) && !(ent->pte & 2) && (cpl || (cpu->cr0 & 0x10000)) ||
	    cpl && !(ent->pte & 4)) {
		cpu->cr2 = laddr;
		cpu->excno = EX_PF;
		cpu->excerr = 1;
		if (rwm & 2)
			cpu->excerr |= 2;
		if (cpl)
			cpu->excerr |= 4;
		ent->lpgno = -1;
		return false;
	}
	*paddr = (ent->pte & ~0xfff) | (laddr & 0xfff);
	if (rwm & 2) *(ent->ppte) |= 1 << 6; // dirty bit
	return true;
}

static bool translate_laddr(CPUI386 *cpu, OptAddr *res, int rwm, uword laddr, int size, int cpl)
{
	if (cpu->cr0 & CR0_PG) {
		uword lpgno = laddr >> 12;
		uword paddr;
		TRY(translate_lpgno(cpu, rwm, lpgno, laddr, cpl, &paddr));
		res->res = ADDR_OK1;
		res->addr1 = paddr;
		if ((laddr & 0xfff) > 0x1000 - size) {
			lpgno++;
			TRY(translate_lpgno(cpu, rwm, lpgno, lpgno << 12, cpl, &paddr));
			res->res = ADDR_OK2;
			res->addr2 = paddr;
		}
	} else {
		res->res = ADDR_OK1;
		res->addr1 = laddr;
	}
	return true;
}

static bool segcheck(CPUI386 *cpu, int rwm, int seg, uword addr, int size)
{
	if (cpu->cr0 & 1) {
		/* null selector check */
		if ((cpu->seg[seg].sel & ~0x3) == 0 && cpu->seg[seg].limit == 0 &&
		    !(cpu->flags & VM)) {
//			fprintf(stderr, "segcheck: seg %d is null %x\n", seg, cpu->seg[seg].sel);
			cpu->excno = EX_GP;
			cpu->excerr = 0;
			return false;
		}
#if 0
		/* limit check */
		bool expand_down = (cpu->seg[seg].flags & 0xc) == 0x4;
		bool over = addr + size - 1 > cpu->seg[seg].limit;
		if (expand_down)
			over = addr <= cpu->seg[seg].limit;
		if (over) {
			fprintf(stderr, "over: addr %08x size %08x limit %08x\n", addr, size, cpu->seg[seg].limit);
			cpu->excno = EX_GP;
			cpu->excerr = 0;
			return false;
		}
		/* todo: readonly check */
#endif
	}
	return true;
}

static bool translate(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr, int size, int cpl)
{
	assert(seg != -1);
	uword laddr = cpu->seg[seg].base + addr;

	TRY(segcheck(cpu, rwm, seg, addr, size));

	return translate_laddr(cpu, res, rwm, laddr, size, cpl);
}

static bool translate8r(CPUI386 *cpu, OptAddr *res, int seg, uword addr)
{
	assert(seg != -1);
	uword laddr = cpu->seg[seg].base + addr;

	TRY(segcheck(cpu, 1, seg, addr, 1));

	if (cpu->cr0 & CR0_PG) {
		uword lpgno = laddr >> 12;
		struct tlb_entry *ent = &(cpu->tlb.tab[lpgno % tlb_size]);
		if (ent->lpgno != lpgno) {
			if (!tlb_refill(cpu, ent, lpgno)) {
				cpu->cr2 = laddr;
				cpu->excno = EX_PF;
				cpu->excerr = 0;
				if (cpu->cpl)
					cpu->excerr |= 4;
				return false;
			}
		}
		if (cpu->cpl && !(ent->pte & 4)) {
			cpu->cr2 = laddr;
			cpu->excno = EX_PF;
			cpu->excerr = 1;
			if (cpu->cpl)
				cpu->excerr |= 4;
			ent->lpgno = -1;
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
	return translate(cpu, res, rwm, seg, addr, 1, cpu->cpl);
}

static bool translate16(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr)
{
	return translate(cpu, res, rwm, seg, addr, 2, cpu->cpl);
}

static bool translate32(CPUI386 *cpu, OptAddr *res, int rwm, int seg, uword addr)
{
	return translate(cpu, res, rwm, seg, addr, 4, cpu->cpl);
}

static bool in_iomem(uword addr)
{
	return addr >= 0xa0000 && addr < 0xc0000 || addr >= 0xe0000000;
}

static u8 load8(CPUI386 *cpu, OptAddr *res)
{
	uword addr = res->addr1;
	if (in_iomem(addr) && cpu->iomem_read8)
		return cpu->iomem_read8(cpu->iomem, addr);
	if (addr >= cpu->phys_mem_size) {
		return 0;
	}
	return ((u8 *) cpu->phys_mem)[addr];
}

static u16 load16(CPUI386 *cpu, OptAddr *res)
{
	if (in_iomem(res->addr1) && cpu->iomem_read16)
		return cpu->iomem_read16(cpu->iomem, res->addr1);
	if (res->addr1 >= cpu->phys_mem_size) {
		return 0;
	}
	u8 *mem = (u8 *) cpu->phys_mem;
	if (res->res == ADDR_OK1)
		return mem[res->addr1] | (mem[res->addr1 + 1] << 8);
	else
		return mem[res->addr1] | (mem[res->addr2] << 8);
}

static u32 load32(CPUI386 *cpu, OptAddr *res)
{
	if (in_iomem(res->addr1) && cpu->iomem_read32)
		return cpu->iomem_read32(cpu->iomem, res->addr1);
	if (res->addr1 >= cpu->phys_mem_size) {
		return 0;
	}
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
	uword addr = res->addr1;
	if (in_iomem(addr) && cpu->iomem_write8) {
		cpu->iomem_write8(cpu->iomem, addr, val);
		return;
	}
	if (addr >= cpu->phys_mem_size) {
		return;
	}
	((u8 *) cpu->phys_mem)[addr] = val;
}

static void store16(CPUI386 *cpu, OptAddr *res, u16 val)
{
	if (in_iomem(res->addr1) && cpu->iomem_write16) {
		cpu->iomem_write16(cpu->iomem, res->addr1, val);
		return;
	}
	if (res->addr1 >= cpu->phys_mem_size) {
		return;
	}
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
	if (in_iomem(res->addr1) && cpu->iomem_write32) {
		cpu->iomem_write32(cpu->iomem, res->addr1, val);
		return;
	}
	if (res->addr1 >= cpu->phys_mem_size) {
		return;
	}
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

#define LOADSTORE(BIT) \
bool cpu_load ## BIT(CPUI386 *cpu, int seg, uword addr, u ## BIT *res) \
{ \
	OptAddr o; \
	TRY(translate ## BIT(cpu, &o, 1, seg, addr)); \
	*res = load ## BIT(cpu, &o); \
	return true; \
} \
\
bool cpu_store ## BIT(CPUI386 *cpu, int seg, uword addr, u ## BIT val) \
{ \
	OptAddr o; \
	TRY(translate ## BIT(cpu, &o, 2, seg, addr)); \
	store ## BIT(cpu, &o, val); \
	return true; \
} \

LOADSTORE(8)
LOADSTORE(16)
LOADSTORE(32)

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
	TRY(translate8r(cpu, &res, SEG_CS, cpu->next_ip));
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

/* insts decode && execute */
static bool modsib32(CPUI386 *cpu, int mod, int rm, uword *addr, int *seg)
{
	if (rm == 4) {
		u8 sib;
		TRY(fetch8(cpu, &sib));
		int b = sib & 7;
		if (b == 5 && mod == 0) {
			TRY(fetch32(cpu, addr));
		} else {
			*addr = REGi(b);
			// sp bp as base register
			if ((b == 4 || b == 5) && *seg == -1)
				*seg = SEG_SS;
		}
		int i = (sib >> 3) & 7;
		if (i != 4)
			*addr += REGi(i) << (sib >> 6);
	} else if (rm == 5 && mod == 0) {
		TRY(fetch32(cpu, addr));
	} else {
		*addr = REGi(rm);
		// bp as base register
		if (rm == 5 && *seg == -1)
			*seg = SEG_SS;
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
	if (*seg == -1)
		*seg = SEG_DS;
	return true;
}

static bool modsib16(CPUI386 *cpu, int mod, int rm, uword *addr, int *seg)
{
	if (rm == 6 && mod == 0) {
		u16 imm16;
		TRY(fetch16(cpu, &imm16));
		*addr = imm16;
	} else {
		switch(rm) {
		case 0: *addr = REGi(3) + REGi(6); break;
		case 1: *addr = REGi(3) + REGi(7); break;
		case 2: *addr = REGi(5) + REGi(6); break;
		case 3: *addr = REGi(5) + REGi(7); break;
		case 4: *addr = REGi(6); break;
		case 5: *addr = REGi(7); break;
		case 6: *addr = REGi(5); break;
		case 7: *addr = REGi(3); break;
		}
		if (mod == 1) {
			u8 imm8;
			TRY(fetch8(cpu, &imm8));
			*addr += (s8) imm8;
		} else if (mod == 2) {
			u16 imm16;
			TRY(fetch16(cpu, &imm16));
			*addr += imm16;
		}
		*addr &= 0xffff;
	}
	if (*seg == -1) {
		if (rm == 2 || rm == 3)
			*seg = SEG_SS;
		else if (mod != 0 && rm == 6)
			*seg = SEG_SS;
		else
			*seg = SEG_DS;
	}
	return true;
}

static bool modsib(CPUI386 *cpu, int adsz16, int mod, int rm, uword *addr, int *seg)
{
	if (adsz16) return modsib16(cpu, mod, rm, addr, seg);
	else return modsib32(cpu, mod, rm, addr, seg);
}

static bool read_desc(CPUI386 *cpu, int sel, uword *w1, uword *w2)
{
	OptAddr meml;
	sel = sel & 0xffff;
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
		cpu->excerr = sel & ~0x3;
		fprintf(stderr, "read_desc: sel %04x base %x limit %x off %x\n", sel, base, limit, off);
		return false;
	}
	if (w1) {
		TRY(translate_laddr(cpu, &meml, 1, base + off, 4, 0));
		*w1 = load32(cpu, &meml);
	}
	TRY(translate_laddr(cpu, &meml, 1, base + off + 4, 4, 0));
	*w2 = load32(cpu, &meml);
	return true;
}

static bool set_seg(CPUI386 *cpu, int seg, int sel)
{
	sel = sel & 0xffff;
	if (!(cpu->cr0 & 1) || (cpu->flags & VM)) {
		cpu->seg[seg].sel = sel;
		cpu->seg[seg].base = sel << 4;
		cpu->seg[seg].limit = 0xffff;
		cpu->seg[seg].flags = 0; // D_BIT is not set
		if (seg == SEG_CS)
			cpu->cpl = cpu->flags & VM ? 3 : 0;
		return true;
	}

	uword off = sel & ~0x7;
	uword w1, w2;
	TRY(read_desc(cpu, sel, &w1, &w2));

	int p = (w2 >> 15) & 1;
	if ((off != 0 || (sel & 0x4)) && !p) {
//		fprintf(stderr, "set seg: seg %d not present %0x\n", seg, sel);
		cpu->excno = EX_NP;
		cpu->excerr = sel & ~0x3;
		return false;
	}

	cpu->seg[seg].sel = sel;
	cpu->seg[seg].base = (w1 >> 16) | ((w2 & 0xff) << 16) | (w2 & 0xff000000);
	cpu->seg[seg].limit = (w2 & 0xf0000) | (w1 & 0xffff);
	if (w2 & 0x00800000)
		cpu->seg[seg].limit = (cpu->seg[seg].limit << 12) | 0xfff;
	cpu->seg[seg].flags = (w2 >> 8) & 0xffff; // (w2 >> 20) & 0xf;
	if (seg == SEG_CS) {
//		if ((sel & 3) != cpu->cpl)
//			fprintf(stderr, "set_seg: PVL %d => %d\n", cpu->cpl, sel & 3);
		cpu->cpl = sel & 3;
	}

	return true;
}

static void clear_segs(CPUI386 *cpu)
{
	int segs[] = { SEG_DS, SEG_ES, SEG_FS, SEG_GS };
	for (int i = 0; i < 4; i++) {
		uword w2 = cpu->seg[segs[i]].flags << 8;
		bool is_dataseg = !((w2 >> 11) & 1);
		int dpl = (w2 >> 13) & 0x3;
		bool conforming = (w2 >> 8) & 0x4;
		if (is_dataseg || !conforming) {
			if (dpl < cpu->cpl) {
				cpu->seg[segs[i]].sel = 0;
				cpu->seg[segs[i]].base = 0;
				cpu->seg[segs[i]].limit = 0;
				cpu->seg[segs[i]].flags = 0;
			}
		}
	}
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
#define IG9(...)

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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, laddr ## BIT, saddr ## BIT) \
	}

#define Eb(...) E_helper(8, , __VA_ARGS__)
#define Ev(...) if (opsz16) { E_helper(16, w, __VA_ARGS__) } else { E_helper(32, d, __VA_ARGS__) }

#define EG_helper(PM, BT, BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (PM && (!(cpu->cr0 & 1) || (cpu->flags & VM))) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	if (mod == 3) { \
		INST ## SUFFIX(rm, reg, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (BT) addr += lreg ## BIT(reg) / BIT * (BIT / 8); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, reg, laddr ## BIT, saddr ## BIT, lreg ## BIT, sreg ## BIT) \
	}

#define EbGb(...) EG_helper(false, false, 8, , __VA_ARGS__)
#define EwGw(...) EG_helper(false, false, 16, , __VA_ARGS__)
#define PMEwGw(...) EG_helper(true, false, 16, , __VA_ARGS__)
#define EvGv(...) if (opsz16) { EG_helper(false, false, 16, w, __VA_ARGS__) } else { EG_helper(false, false, 32, d, __VA_ARGS__) }
#define BTEvGv(...) if (opsz16) { EG_helper(false, true, 16, w, __VA_ARGS__) } else { EG_helper(false, true, 32, d, __VA_ARGS__) }

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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fetch ## BIT(cpu, &imm ## BIT)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, imm ## BIT, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define EbIb(...) EI_helper(8, , __VA_ARGS__)
#define EvIv(...) if (opsz16) { EI_helper(16, w, __VA_ARGS__) } else { EI_helper(32, d, __VA_ARGS__) }

#define EIb_helper(BT, BIT, SUFFIX, rwm, INST) \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fetch8(cpu, &imm8)); \
		imm ## BIT = (s ## BIT) ((s8) imm8); \
		if (BT) addr += imm ## BIT / BIT * (BIT / 8); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(&meml, imm ## BIT, laddr ## BIT, saddr ## BIT, limm, 0) \
	}

#define EvIb(...) if (opsz16) { EIb_helper(false, 16, w, __VA_ARGS__) } else { EIb_helper(false, 32, d, __VA_ARGS__) }
#define BTEvIb(...) if (opsz16) { EIb_helper(true, 16, w, __VA_ARGS__) } else { EIb_helper(true, 32, d, __VA_ARGS__) }

#define E1_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(rm, 1, lreg ## BIT, sreg ## BIT, limm, 0) \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(translate ## BIT(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## SUFFIX(reg, &meml, lreg ## BIT, sreg ## BIT, laddr ## BIT, saddr ## BIT) \
	}

#define GbEb(...) GE_helper(8, , __VA_ARGS__)
#define GvEv(...) if (opsz16) { GE_helper(16, w, __VA_ARGS__) } else { GE_helper(32, d, __VA_ARGS__) }

#define GvM_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX(reg, rm, lreg ## BIT, sreg ## BIT, lreg ## BIT, sreg ## BIT) \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		INST ## SUFFIX(reg, addr, lreg ## BIT, sreg ## BIT, limm, 0) \
	}
#define GvM(...) if (opsz16) { GvM_helper(16, w, __VA_ARGS__) } else { GvM_helper(32, d, __VA_ARGS__) }

#define GvMp_helper(BIT, SUFFIX, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		cpu->excno = EX_UD; \
		return false; \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		INST ## SUFFIX(reg, addr, lreg ## BIT, sreg ## BIT, limm, 0) \
	}
#define GvMp(...) if (opsz16) { GvMp_helper(16, w, __VA_ARGS__) } else { GvMp_helper(32, d, __VA_ARGS__) }

#define GE_helper2(BIT, SUFFIX, BIT2, SUFFIX2, rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		INST ## SUFFIX ## SUFFIX2(reg, rm, lreg ## BIT, sreg ## BIT, lreg ## BIT2, sreg ## BIT2) \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		INST ## w(2, 0, lreg16, sreg16, lreg16, sreg16) \
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
	if (adsz16) { \
		u16 addr16; \
		TRY(fetch16(cpu, &addr16)); \
		addr = addr16; \
	} else { \
		TRY(fetch32(cpu, &addr)); \
	} \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	TRY(translate8(cpu, &meml, rwm, curr_seg, addr)); \
	INST(0, &meml, lreg8, sreg8, laddr8, saddr8)

#define AXOv(rwm, INST) \
	if (adsz16) { \
		u16 addr16; \
		TRY(fetch16(cpu, &addr16)); \
		addr = addr16; \
	} else { \
		TRY(fetch32(cpu, &addr)); \
	} \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	if (opsz16) { \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## w(0, &meml, lreg16, sreg16, laddr16, saddr16) \
	} else { \
		TRY(translate32(cpu, &meml, rwm, curr_seg, addr)); \
		INST ## d(0, &meml, lreg32, sreg32, laddr32, saddr32) \
	}

#define ObAL(rwm, INST) \
	if (adsz16) { \
		u16 addr16; \
		TRY(fetch16(cpu, &addr16)); \
		addr = addr16; \
	} else { \
		TRY(fetch32(cpu, &addr)); \
	} \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	TRY(translate8(cpu, &meml, rwm, curr_seg, addr)); \
	INST(&meml, 0, laddr8, saddr8, lreg8, sreg8)

#define OvAX(rwm, INST) \
	if (adsz16) { \
		u16 addr16; \
		TRY(fetch16(cpu, &addr16)); \
		addr = addr16; \
	} else { \
		TRY(fetch32(cpu, &addr)); \
	} \
	if (curr_seg == -1) curr_seg = SEG_DS; \
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

#define Jv(rwm, INST) \
	if (adsz16) { \
		u16 imm16; \
		TRY(fetch16(cpu, &imm16)); \
		INST ## w(imm16, limm, 0); \
	} else { \
		u32 imm32; \
		TRY(fetch32(cpu, &imm32)); \
		INST ## d(imm32, limm, 0); \
	}
#define Av Iv

#define Ap(rwm, INST) \
	u16 seg; \
	if (opsz16) { \
		u16 addr16; \
		TRY(fetch16(cpu, &addr16)); \
		addr = addr16; \
	} else { \
		TRY(fetch32(cpu, &addr)); \
	} \
	TRY(fetch16(cpu, &seg)); \
	INST(addr, seg)

#define Ep(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		cpu->excno = EX_UD; \
		return false; \
	} else { \
		u16 seg; \
		u32 off; \
		OptAddr moff, mseg; \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (opsz16) { \
			TRY(translate16(cpu, &moff, rwm, curr_seg, addr)); \
			TRY(translate16(cpu, &mseg, rwm, curr_seg, addr + 2)); \
			off = laddr16(&moff); \
			seg = laddr16(&mseg); \
		} else { \
			TRY(translate32(cpu, &moff, rwm, curr_seg, addr)); \
			TRY(translate16(cpu, &mseg, rwm, curr_seg, addr + 4)); \
			off = laddr32(&moff); \
			seg = laddr16(&mseg); \
		} \
		INST(off, seg) \
	}

#define Ms(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		cpu->excno = EX_UD; \
		return false; \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		INST(addr) \
	}

#define Ew(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (opsz16) { \
			INST(rm, lreg16, sreg16) \
		} else { \
			INST(rm, lreg32, sreg32) \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST(&meml, laddr16, saddr16) \
	}

#define EwSw(rwm, INST) \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (opsz16) { \
			INST(rm, reg, lreg16, sreg16, lseg, 0) \
		} else { \
			INST(rm, reg, lreg32, sreg32, lseg, 0) \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
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
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(translate16(cpu, &meml, rwm, curr_seg, addr)); \
		INST(reg, &meml,lseg, 0, laddr16, saddr16) \
	}

#define limm(i) i
#define lreg8(i) ((u8) ((i) > 3 ? REGi((i) - 4) >> 8 : REGi((i))))
#define sreg8(i, v) ((i) > 3 ? \
		     (REGi((i) - 4) = REGi((i) - 4) & (wordmask ^ 0xff00) | ((v) & 0xff) << 8) : \
		     (REGi((i)) = REGi((i)) & (wordmask ^ 0xff) | (v) & 0xff))
#define lreg16(i) ((u16) REGi((i)))
#define sreg16(i, v) (REGi((i)) = REGi((i)) & (wordmask ^ 0xffff) | (v) & 0xffff)
#define lreg32(i) ((u32) REGi((i)))
#define sreg32(i, v) (REGi((i)) = REGi((i)) & (wordmask ^ 0xffffffff) | (v) & 0xffffffff)
#define laddr8(addr) load8(cpu, addr)
#define saddr8(addr, v) store8(cpu, addr, v)
#define laddr16(addr) load16(cpu, addr)
#define saddr16(addr, v) store16(cpu, addr, v)
#define laddr32(addr) load32(cpu, addr)
#define saddr32(addr, v) store32(cpu, addr, v)
#define lseg(i) ((u16) SEGi((i)))
#define set_sp(v, mask) (sreg32(4, (v) & mask | lreg32(4) & ~mask))

/*
 * instructions
 */
#define ACOP_helper(NAME1, NAME2, BIT, OP, a, b, la, sa, lb, sb) \
	int cf = get_CF(cpu); \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = sext ## BIT(cpu->cc.src1 OP cpu->cc.src2 OP cf); \
	cpu->cc.op = cf ? CC_ ## NAME1 : CC_ ## NAME2; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define AOP0_helper(NAME, BIT, OP, a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = sext ## BIT(cpu->cc.src1 OP cpu->cc.src2); \
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

#define INCDEC_helper(NAME, BIT, OP, a, la, sa) \
	int cf = get_CF(cpu); \
	cpu->cc.dst = sext ## BIT(sext ## BIT(la(a)) OP 1); \
	cpu->cc.op = CC_ ## NAME ## BIT; \
	if (cf) { \
		cpu->flags |= CF; \
	} else { \
		cpu->flags &= ~CF; \
	} \
	cpu->cc.mask = PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define NEG_helper(BIT, a, la, sa) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.dst = sext ## BIT(-cpu->cc.src1); \
	cpu->cc.op = CC_NEG ## BIT; \
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
	uword y = (lb(b)) & 0x1f; \
	if (y) { \
		cpu->cc.dst = sext ## BIT(x << y); \
		cpu->cc.dst2 = ((x >> (BIT - y)) & 1); \
		cpu->cc.op = CC_SHL; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHLb(...) SHL_helper(8, __VA_ARGS__)
#define SHLw(...) SHL_helper(16, __VA_ARGS__)
#define SHLd(...) SHL_helper(32, __VA_ARGS__)

#define ROL_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y0 = lb(b); \
	uword y = y0 & (BIT - 1); \
	uword res = x; \
	if (y) { \
		res = sext ## BIT((x << y) | (x >> (BIT - y))); \
		sa(a, res); \
	} \
	if (y0) { \
		int cf1 = res & 1; \
		int of1 = (res >> (sizeof(uword) * 8 - 1)) ^ cf1; \
		if (cf1) cpu->flags |= CF; else cpu->flags &= ~CF; \
		if (of1) cpu->flags |= OF; else cpu->flags &= ~OF; \
		cpu->cc.mask &= ~(CF | OF); \
	}

#define ROLb(...) ROL_helper(8, __VA_ARGS__)
#define ROLw(...) ROL_helper(16, __VA_ARGS__)
#define ROLd(...) ROL_helper(32, __VA_ARGS__)

#define RCL_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = ((lb(b)) & 0x1f) % (BIT + 1); \
	if (y) { \
		uword cf = get_CF(cpu); \
		uword res = sext ## BIT((x << y) | (cf << (y - 1)) | (y != 1 ? (x >> (BIT + 1 - y)) : 0)); \
		int cf1 = (x >> (BIT - y)) & 1; \
		int of1 = (res >> (sizeof(uword) * 8 - 1)) ^ cf1; \
		if (cf1) cpu->flags |= CF; else cpu->flags &= ~CF; \
		if (of1) cpu->flags |= OF; else cpu->flags &= ~OF; \
		cpu->cc.mask &= ~(CF | OF); \
		sa(a, res); \
	}

#define RCLb(...) RCL_helper(8, __VA_ARGS__)
#define RCLw(...) RCL_helper(16, __VA_ARGS__)
#define RCLd(...) RCL_helper(32, __VA_ARGS__)

#define RCR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = ((lb(b)) & 0x1f) % (BIT + 1); \
	if (y) { \
		uword cf = get_CF(cpu); \
		uword res = sext ## BIT((x >> y) | (cf << (BIT - y)) | (y != 1 ? (x << (BIT + 1 - y)) : 0)); \
		int cf1 = (sext ## BIT(x << (BIT - y)) >> (BIT - 1)) & 1; \
		int of1 = ((res ^ (res << 1)) >> (BIT - 1)) & 1; \
		if (cf1) cpu->flags |= CF; else cpu->flags &= ~CF; \
		if (of1) cpu->flags |= OF; else cpu->flags &= ~OF; \
		cpu->cc.mask &= ~(CF | OF); \
		sa(a, res); \
	}

#define RCRb(...) RCR_helper(8, __VA_ARGS__)
#define RCRw(...) RCR_helper(16, __VA_ARGS__)
#define RCRd(...) RCR_helper(32, __VA_ARGS__)

#define ROR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y0 = lb(b); \
	uword y = y0 & (BIT - 1); \
	uword res = x; \
	if (y) { \
		res = sext ## BIT((x >> y) | (x << (BIT - y))); \
		sa(a, res); \
	} \
	if (y0) { \
		int cf1 = (res >> (BIT - 1)) & 1; \
		int of1 = ((res ^ (res << 1)) >> (BIT - 1)) & 1; \
		if (cf1) cpu->flags |= CF; else cpu->flags &= ~CF; \
		if (of1) cpu->flags |= OF; else cpu->flags &= ~OF; \
		cpu->cc.mask &= ~(CF | OF); \
	}

#define RORb(...) ROR_helper(8, __VA_ARGS__)
#define RORw(...) ROR_helper(16, __VA_ARGS__)
#define RORd(...) ROR_helper(32, __VA_ARGS__)

#define SHR_helper(BIT, a, b, la, sa, lb, sb) \
	uword x = la(a); \
	uword y = (lb(b)) & 0x1f; \
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
	int count = (lc(c)) & 0x1f; \
	uword x = la(a); \
	uword y = lb(b); \
	if (count) { \
		cpu->cc.src1 = sext ## BIT(x); \
		if (BIT < count) {  /* undocumented */ \
			uword z = x; x = y; y = z; \
			count -= BIT; \
		} \
		cpu->cc.dst = sext ## BIT((x << count) | (y >> (BIT - count))); \
		if (count == 1) { \
			cpu->cc.dst2 = sext ## BIT(x); \
		} else { \
			cpu->cc.dst2 = sext ## BIT((x << (count - 1)) | (count == 1 ? 0 : (y >> (BIT - (count - 1))))); \
		} \
		cpu->cc.op = CC_SHLD; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHLDw(...) SHLD_helper(16, __VA_ARGS__)
#define SHLDd(...) SHLD_helper(32, __VA_ARGS__)

#define SHRD_helper(BIT, a, b, c, la, sa, lb, sb, lc, sc) \
	int count = (lc(c)) & 0x1f; \
	uword x = la(a); \
	uword y = lb(b); \
	if (count) { \
		if (BIT < count) {  /* undocumented */ \
			uword z = x; x = y; y = z; \
			count -= BIT; \
		} \
		cpu->cc.src1 = sext ## BIT(x); \
		cpu->cc.dst = sext ## BIT((x >> count) | (y << (BIT - count))); \
		if (count == 1) { \
			cpu->cc.dst2 = sext ## BIT(x); \
		} else { \
			cpu->cc.dst2 = sext ## BIT((x >> (count - 1)) | (y << (BIT - (count - 1)))); \
		} \
		cpu->cc.op = CC_SHRD; \
		cpu->cc.mask = CF | PF | ZF | SF | OF; \
		sa(a, cpu->cc.dst); \
	}

#define SHRDw(...) SHRD_helper(16, __VA_ARGS__)
#define SHRDd(...) SHRD_helper(32, __VA_ARGS__)

// ">>"
#define SAR_helper(BIT, a, b, la, sa, lb, sb) \
	sword x = sext ## BIT(la(a)); \
	sword y = (lb(b)) & 0x1f; \
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

#define IMUL2w(a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext16(la(a)); \
	cpu->cc.src2 = sext16(lb(b)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.op = CC_IMUL16; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2d(a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext32(la(a)); \
	cpu->cc.src2 = sext32(lb(b)); \
	int64_t res = (int64_t) (s32) cpu->cc.src1 * (int64_t) (s32) cpu->cc.src2; \
	cpu->cc.dst = res; \
	cpu->cc.dst2 = res >> 32; \
	cpu->cc.op = CC_IMUL32; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2wI_helper(BIT, BITI, a, b, c, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(lb(b)); \
	cpu->cc.src2 = sext ## BITI(c); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.op = CC_IMUL ## BIT; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2dI_helper(BIT, BITI, a, b, c, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(lb(b)); \
	cpu->cc.src2 = sext ## BITI(c); \
	int64_t res = (int64_t) (s32) cpu->cc.src1 * (int64_t) (s32) cpu->cc.src2; \
	cpu->cc.dst = res; \
	cpu->cc.dst2 = res >> 32; \
	cpu->cc.op = CC_IMUL ## BIT; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sa(a, cpu->cc.dst);

#define IMUL2wIb(...) IMUL2wI_helper(16, 8, __VA_ARGS__)
#define IMUL2wIw(...) IMUL2wI_helper(16, 16, __VA_ARGS__)
#define IMUL2dIb(...) IMUL2dI_helper(32, 8, __VA_ARGS__)
#define IMUL2dId(...) IMUL2dI_helper(32, 32, __VA_ARGS__)

#define IMULb(a, la, sa) \
	cpu->cc.src1 = sext8(lreg8(0)); \
	cpu->cc.src2 = sext8(la(a)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
	cpu->cc.op = CC_IMUL8; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst);

#define IMULw(a, la, sa) \
	cpu->cc.src1 = sext16(lreg16(0)); \
	cpu->cc.src2 = sext16(la(a)); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
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
	cpu->cc.dst = sext16(cpu->cc.src1 * cpu->cc.src2); \
	cpu->cc.op = CC_MUL8; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	sreg16(0, cpu->cc.dst);

#define MULw(a, la, sa) \
	cpu->cc.src1 = lreg16(0); \
	cpu->cc.src2 = la(a); \
	cpu->cc.dst = cpu->cc.src1 * cpu->cc.src2; \
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
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	sword res = src1 / src2; \
	if (res > 127 || res < -128) { cpu->excno = EX_DE; return false; } \
	sreg8(0, res); \
	sreg8(4, src1 % src2);

#define IDIVw(a, la, sa) \
	sword src1 = sext32(lreg16(0) | (lreg16(2)<< 16)); \
	sword src2 = sext16(la(a)); \
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	sword res = src1 / src2; \
	if (res > 32767 || res < -32768) { cpu->excno = EX_DE; return false; } \
	sreg16(0, res); \
	sreg16(2, src1 % src2);

#define IDIVd(a, la, sa) \
	int64_t src1 = (((uint64_t) lreg32(2)) << 32) | lreg32(0); \
	int64_t src2 = (sword) (la(a));	\
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	int64_t res = src1 / src2; \
	if (res > 2147483647 || res < -2147483648) { cpu->excno = EX_DE; return false; } \
	sreg32(0, res); \
	sreg32(2, src1 % src2);

#define DIVb(a, la, sa) \
	uword src1 = lreg16(0); \
	uword src2 = la(a); \
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	uword res = src1 / src2; \
	if (res > 0xff) { cpu->excno = EX_DE; return false; } \
	sreg8(0, res); \
	sreg8(4, src1 % src2);

#define DIVw(a, la, sa) \
	uword src1 = lreg16(0) | (lreg16(2)<< 16); \
	uword src2 = la(a); \
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	uword res = src1 / src2; \
	if (res > 0xffff) { cpu->excno = EX_DE; return false; } \
	sreg16(0, res); \
	sreg16(2, src1 % src2);

#define DIVd(a, la, sa) \
	uint64_t src1 = (((uint64_t) lreg32(2)) << 32) | lreg32(0); \
	uint64_t src2 = la(a); \
	if (src2 == 0) { cpu->excno = EX_DE; return false; } \
	uint64_t res = src1 / src2; \
	if (res > 0xffffffff) { cpu->excno = EX_DE; return false; } \
	sreg32(0, res); \
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
#define MOVSeg(a, b, la, sa, lb, sb) \
	if (a == SEG_CS) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	if (a == SEG_SS) stepcount++; \
	TRY(set_seg(cpu, a, lb(b)));
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
	sa(a, lb(b));
#define LEAw LEAd

#define CBW_CWDE() \
	if (opsz16) sreg16(0, sext8(lreg8(0))); \
	else sreg32(0, sext16(lreg16(0)));

#define CWD_CDQ() \
	if (opsz16) sreg16(2, sext16(-(sext16(lreg16(0)) >> 31))); \
	else sreg32(2, sext32(-(sext32(lreg32(0)) >> 31)));

#define MOVFC() \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	if (reg == 0) { \
		sreg32(rm, cpu->cr0); \
	} else if (reg == 2) { \
		sreg32(rm, cpu->cr2); \
	} else if (reg == 3) { \
		sreg32(rm, cpu->cr3); \
	} else if (reg == 4) { \
		sreg32(rm, 0); \
	} else { \
		cpu->excno = EX_UD; \
		return false; \
	}

#define MOVTC() \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	if (reg == 0) { \
		u32 new_cr0 = lreg32(rm); \
		if ((new_cr0 ^ cpu->cr0) & (CR0_PG | 1)) \
			tlb_clear(cpu); \
		cpu->cr0 = new_cr0; \
	} else if (reg == 2) { \
		cpu->cr2 = lreg32(rm); \
	} else if (reg == 3) { \
		cpu->cr3 = lreg32(rm); \
		tlb_clear(cpu); \
	} else if (reg == 4) { \
	} else { \
		cpu->excno = EX_UD; \
		return false; \
	}

#define INT3() \
	cpu->excno = EX_BP; \
	cpu->ip = cpu->next_ip; \
	return false;

#define INTO() \
	if (get_OF(cpu)) { \
		cpu->excno = EX_OF; \
		cpu->ip = cpu->next_ip; \
		return false; \
	}

static bool call_isr(CPUI386 *cpu, int no, bool pusherr, int ext);

#define INT(i, li, _) \
	/*fprintf(stderr, "int %02x %08x %04x:%08x\n", li(i), cpu->gpr[0], cpu->seg[SEG_CS].sel, cpu->ip);*/ \
	if ((cpu->flags & VM)) { \
		if(get_IOPL(cpu) < 3) { \
			cpu->excno = EX_GP; \
			cpu->excerr = 0; \
			return false; \
		} \
	} \
	uword oldip = cpu->ip; \
	cpu->ip = cpu->next_ip; \
	if (!call_isr(cpu, li(i), false, 0)) { \
		cpu->ip = oldip; \
		return false; \
	}

#define IRET() \
	if ((cpu->cr0 & 1) && (!(cpu->flags & VM) || get_IOPL(cpu) < 3)) { \
		TRY(pmret(cpu, opsz16, 0, true)); \
	} else { \
		if (!opsz16) cpu_abort(cpu, -201); \
		OptAddr meml1, meml2, meml3; \
		uword sp = lreg32(4); \
		/* ip */ TRY(translate16(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
		uword newip = laddr16(&meml1); \
		/* cs */ TRY(translate16(cpu, &meml2, 1, SEG_SS, (sp + 2) & sp_mask)); \
		int newcs = laddr16(&meml2); \
		/* flags */ TRY(translate16(cpu, &meml3, 1, SEG_SS, (sp + 4) & sp_mask)); \
		uword oldflags = cpu->flags; \
		if (cpu->flags & VM) cpu->flags = (cpu->flags & (0xffff0000 | IOPL)) | (laddr16(&meml3) & ~IOPL); \
		else cpu->flags = (cpu->flags & 0xffff0000) | laddr16(&meml3); \
		cpu->flags &= EFLAGS_MASK; \
		cpu->flags |= 0x2; \
		if (!set_seg(cpu, SEG_CS, newcs)) { cpu->flags = oldflags; return false; } \
		cpu->cc.mask = 0; \
		set_sp(sp + 6, sp_mask); \
		cpu->next_ip = newip; \
	} \
	if (cpu->intr && (cpu->flags & IF)) return true;

#define RETFARw(i, li, _) \
	if ((cpu->cr0 & 1) && !(cpu->flags & VM)) { \
		TRY(pmret(cpu, opsz16, li(i), false)); \
	} else { \
		if (opsz16) { \
			OptAddr meml1, meml2; \
			uword sp = lreg32(4); \
			/* ip */ TRY(translate16(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
			uword newip = laddr16(&meml1); \
			/* cs */ TRY(translate16(cpu, &meml2, 1, SEG_SS, (sp + 2) & sp_mask)); \
			int newcs = laddr16(&meml2); \
			TRY(set_seg(cpu, SEG_CS, newcs)); \
			set_sp(sp + 4 + li(i), sp_mask); \
			cpu->next_ip = newip; \
		} else { \
			OptAddr meml1, meml2; \
			uword sp = lreg32(4); \
			/* ip */ TRY(translate32(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
			uword newip = laddr32(&meml1); \
			/* cs */ TRY(translate32(cpu, &meml2, 1, SEG_SS, (sp + 4) & sp_mask)); \
			int newcs = laddr32(&meml2); \
			TRY(set_seg(cpu, SEG_CS, newcs)); \
			set_sp(sp + 8 + li(i), sp_mask); \
			cpu->next_ip = newip; \
		} \
	}

#define RETFAR() RETFARw(0, limm, 0)

#define HLT() \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	cpu->halt = true; return true;
#define NOP()

#define LAHF() \
	refresh_flags(cpu); \
	cpu->cc.mask = 0; \
	sreg8(4, cpu->flags);

#define SAHF() \
	cpu->cc.mask &= OF; \
	cpu->flags = cpu->flags & (wordmask ^ 0xff) | lreg8(4); \
	cpu->flags &= EFLAGS_MASK;

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
	if (get_IOPL(cpu) < cpu->cpl) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	cpu->flags &= ~IF;

#define STI() \
	if (get_IOPL(cpu) < cpu->cpl) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	cpu->flags |= IF; \
	if (cpu->intr) return true;

#define CLD() \
	cpu->flags &= ~DF;

#define STD() \
	cpu->flags |= DF;

#define PUSHb(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	uword val = sext8(la(a)); \
	if (opsz16) { \
		TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask)); \
		set_sp(sp - 2, sp_mask); \
		saddr16(&meml1, val); \
	} else { \
		TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask)); \
		set_sp(sp - 4, sp_mask); \
		saddr32(&meml1, val); \
	}

#define PUSHw(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	uword val = sext16(la(a)); \
	TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask)); \
	set_sp(sp - 2, sp_mask); \
	saddr16(&meml1, val);

#define PUSHd(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	uword val = sext32(la(a)); \
	TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask)); \
	set_sp(sp - 4, sp_mask); \
	saddr32(&meml1, val);

#define POPRegw(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
	u16 src = laddr16(&meml1); \
	set_sp(sp + 2, sp_mask); \
	sa(a, src);

#define POPRegd(a, la, sa) \
	OptAddr meml1; \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
	u32 src = laddr32(&meml1); \
	set_sp(sp + 4, sp_mask); \
	sa(a, src);

#define POPw() \
	OptAddr meml1; \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
	u16 src = laddr16(&meml1); \
	set_sp(sp + 2, sp_mask); \
	if (mod == 3) { \
		sreg16(rm, src); \
	} else { \
		if (!modsib(cpu, adsz16, mod, rm, &addr, &curr_seg) || \
		    !translate16(cpu, &meml, 2, curr_seg, addr)) { \
			set_sp(sp, sp_mask); \
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
	TRY(translate32(cpu, &meml1, 1, SEG_SS, sp & sp_mask)); \
	u32 src = laddr32(&meml1); \
	set_sp(sp + 4, sp_mask); \
	if (mod == 3) { \
		sreg32(rm, src); \
	} else { \
		if (!modsib(cpu, adsz16, mod, rm, &addr, &curr_seg) || \
		    !translate32(cpu, &meml, 2, curr_seg, addr)) { \
			set_sp(sp, sp_mask); \
			return false; \
		} \
		saddr32(&meml, src); \
	}
#define POP() if (opsz16) { POPw(); } else { POPd(); }

#define PUSHF() \
	if ((cpu->flags & VM) && get_IOPL(cpu) < 3) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 2, SEG_SS, (sp - 2) & sp_mask)); \
		refresh_flags(cpu); \
		cpu->cc.mask = 0; \
		set_sp(sp - 2, sp_mask); \
		saddr16(&meml, cpu->flags); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate32(cpu, &meml, 2, SEG_SS, (sp - 4) & sp_mask)); \
		refresh_flags(cpu); \
		cpu->cc.mask = 0; \
		set_sp(sp - 4, sp_mask); \
		saddr32(&meml, cpu->flags & ~(RF | VM)); \
	}

#define EFLAGS_MASK_386 0x37fd7
#define EFLAGS_MASK_486 0x77fd7
#define EFLAGS_MASK_586 0x277fd7
#define EFLAGS_MASK EFLAGS_MASK_486

#define POPF() \
	if ((cpu->flags & VM) && get_IOPL(cpu) < 3) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	uword mask = VM; \
	if (cpu->cr0 & 1) { \
		if (cpu->cpl > 0) mask |= IOPL; \
		if (get_IOPL(cpu) < cpu->cpl) mask |= IF; \
	} \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 2, sp_mask); \
		cpu->flags = (cpu->flags & (0xffff0000 | mask)) | (laddr16(&meml) & ~mask); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate32(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 4, sp_mask); \
		cpu->flags = (cpu->flags & mask) | (laddr32(&meml) & ~mask); \
	} \
	cpu->flags &= EFLAGS_MASK; \
	cpu->flags |= 0x2; \
	cpu->cc.mask = 0; \
	if (cpu->intr && (cpu->flags & IF)) return true;

#define PUSHSeg(seg) \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 2, SEG_SS, (sp - 2) & sp_mask)); \
		set_sp(sp - 2, sp_mask); \
		saddr16(&meml, lseg(seg)); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 2, SEG_SS, (sp - 4) & sp_mask)); \
		set_sp(sp - 4, sp_mask); \
		saddr16(&meml, lseg(seg)); \
	}
#define PUSH_ES() PUSHSeg(SEG_ES)
#define PUSH_CS() PUSHSeg(SEG_CS)
#define PUSH_SS() PUSHSeg(SEG_SS)
#define PUSH_DS() PUSHSeg(SEG_DS)
#define PUSH_FS() PUSHSeg(SEG_FS)
#define PUSH_GS() PUSHSeg(SEG_GS)

#define POPSeg(seg) \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		TRY(set_seg(cpu, seg, laddr16(&meml))); \
		set_sp(sp + 2, sp_mask); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		TRY(set_seg(cpu, seg, laddr16(&meml))); \
		set_sp(sp + 4, sp_mask); \
	}
#define POP_ES() POPSeg(SEG_ES)
#define POP_SS() POPSeg(SEG_SS) stepcount++;
#define POP_DS() POPSeg(SEG_DS)
#define POP_FS() POPSeg(SEG_FS)
#define POP_GS() POPSeg(SEG_GS)

#define PUSHA_helper(BIT, BYTE) \
	uword sp = lreg32(4); \
	OptAddr meml1, meml2, meml3, meml4; \
	OptAddr meml5, meml6, meml7, meml8; \
	TRY(translate ## BIT(cpu, &meml1, 2, SEG_SS, (sp - BYTE * 1) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml2, 2, SEG_SS, (sp - BYTE * 2) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml3, 2, SEG_SS, (sp - BYTE * 3) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml4, 2, SEG_SS, (sp - BYTE * 4) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml5, 2, SEG_SS, (sp - BYTE * 5) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml6, 2, SEG_SS, (sp - BYTE * 6) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml7, 2, SEG_SS, (sp - BYTE * 7) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml8, 2, SEG_SS, (sp - BYTE * 8) & sp_mask)); \
	saddr ## BIT(&meml1, lreg ## BIT(0)); \
	saddr ## BIT(&meml2, lreg ## BIT(1)); \
	saddr ## BIT(&meml3, lreg ## BIT(2)); \
	saddr ## BIT(&meml4, lreg ## BIT(3)); \
	saddr ## BIT(&meml5, sp); \
	saddr ## BIT(&meml6, lreg ## BIT(5)); \
	saddr ## BIT(&meml7, lreg ## BIT(6)); \
	saddr ## BIT(&meml8, lreg ## BIT(7)); \
	set_sp(sp - BYTE * 8, sp_mask);
#define PUSHA() if (opsz16) { PUSHA_helper(16, 2) } else { PUSHA_helper(32, 4) }

#define POPA_helper(BIT, BYTE) \
	uword sp = lreg32(4); \
	OptAddr meml1, meml2, meml3, meml4; \
	OptAddr meml5, meml6, meml7; \
	TRY(translate ## BIT(cpu, &meml1, 1, SEG_SS, (sp + BYTE * 0) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml2, 1, SEG_SS, (sp + BYTE * 1) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml3, 1, SEG_SS, (sp + BYTE * 2) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml4, 1, SEG_SS, (sp + BYTE * 4) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml5, 1, SEG_SS, (sp + BYTE * 5) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml6, 1, SEG_SS, (sp + BYTE * 6) & sp_mask)); \
	TRY(translate ## BIT(cpu, &meml7, 1, SEG_SS, (sp + BYTE * 7) & sp_mask)); \
	sreg ## BIT(7, laddr ## BIT(&meml1)); \
	sreg ## BIT(6, laddr ## BIT(&meml2)); \
	sreg ## BIT(5, laddr ## BIT(&meml3)); \
	sreg ## BIT(3, laddr ## BIT(&meml4)); \
	sreg ## BIT(2, laddr ## BIT(&meml5)); \
	sreg ## BIT(1, laddr ## BIT(&meml6)); \
	sreg ## BIT(0, laddr ## BIT(&meml7)); \
	set_sp(sp + BYTE * 8, sp_mask);
#define POPA() if (opsz16) { POPA_helper(16, 2) } else { POPA_helper(32, 4) }

// string operations
#define stdi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, lreg ## ABIT(7))); \
	saddr ## BIT(&meml, ax); \
	sreg ## ABIT(7, lreg ## ABIT(7) + dir);

#define ldsi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, lreg ## ABIT(6))); \
	ax = laddr ## BIT(&meml); \
	sreg ## ABIT(6, lreg ## ABIT(6) + dir);

#define lddi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 1, SEG_ES, lreg ## ABIT(7))); \
	ax = laddr ## BIT(&meml); \
	sreg ## ABIT(7, lreg ## ABIT(7) + dir);

#define ldsistdi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, lreg ## ABIT(6))); \
	ax = laddr ## BIT(&meml); \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, lreg ## ABIT(7))); \
	saddr ## BIT(&meml, ax); \
	sreg ## ABIT(6, lreg ## ABIT(6) + dir); \
	sreg ## ABIT(7, lreg ## ABIT(7) + dir);

#define ldsilddi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, lreg ## ABIT(6))); \
	ax0 = laddr ## BIT(&meml); \
	TRY(translate ## BIT(cpu, &meml, 1, SEG_ES, lreg ## ABIT(7))); \
	ax = laddr ## BIT(&meml); \
	sreg ## ABIT(6, lreg ## ABIT(6) + dir); \
	sreg ## ABIT(7, lreg ## ABIT(7) + dir);

#define xdir8 int dir = (cpu->flags & DF) ? -1 : 1;
#define xdir16 int dir = (cpu->flags & DF) ? -2 : 2;
#define xdir32 int dir = (cpu->flags & DF) ? -4 : 4;

#define STOS_helper(BIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	xdir ## BIT \
	u ## BIT ax = REGi(0); \
	if (rep == 0) { \
		if (adsz16) { stdi(BIT, 16) } else { stdi(BIT, 32) } \
	} else { \
		if (adsz16) { \
			while (lreg16(1)) { \
				stdi(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
			} \
		} else { \
			while (lreg32(1)) { \
				stdi(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
			} \
		} \
	}

#define LODS_helper(BIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		if (adsz16) { ldsi(BIT, 16) } else { ldsi(BIT, 32) } \
		sreg ## BIT(0, ax); \
	} else { \
		if (adsz16) { \
			while (lreg16(1)) { \
				ldsi(BIT, 16) \
				sreg ## BIT(0, ax); \
				sreg16(1, lreg16(1) - 1); \
			} \
		} else { \
			while (lreg32(1)) { \
				ldsi(BIT, 32) \
				sreg ## BIT(0, ax); \
				sreg32(1, lreg32(1) - 1); \
			} \
		} \
	}

#define SCAS_helper(BIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	xdir ## BIT \
	u ## BIT ax0 = REGi(0); \
	u ## BIT ax; \
	if (rep == 0) { \
		if (adsz16) { lddi(BIT, 16) } else { lddi(BIT, 32) } \
		cpu->cc.src1 = sext ## BIT(ax0); \
		cpu->cc.src2 = sext ## BIT(ax); \
		cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
		cpu->cc.op = CC_SUB; \
		cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	} else { \
		if (adsz16) { \
			while (lreg16(1)) { \
				lddi(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
				cpu->cc.src1 = sext ## BIT(ax0); \
				cpu->cc.src2 = sext ## BIT(ax); \
				cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
				cpu->cc.op = CC_SUB; \
				cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
				bool zf = get_ZF(cpu); \
				if (zf && rep == 2 || !zf && rep == 1) break; \
			} \
		} else { \
			while (lreg32(1)) { \
				lddi(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
				cpu->cc.src1 = sext ## BIT(ax0); \
				cpu->cc.src2 = sext ## BIT(ax); \
				cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
				cpu->cc.op = CC_SUB; \
				cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
				bool zf = get_ZF(cpu); \
				if (zf && rep == 2 || !zf && rep == 1) break; \
			} \
		} \
	}

#define MOVS_helper(BIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		if (adsz16) { ldsistdi(BIT, 16) } else { ldsistdi(BIT, 32) } \
	} else { \
		if (adsz16) { \
			while (lreg16(1)) { \
				ldsistdi(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
			} \
		} else { \
			while (lreg32(1)) { \
				ldsistdi(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
			} \
		} \
	}

#define CMPS_helper(BIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	xdir ## BIT \
	u ## BIT ax0, ax; \
	if (rep == 0) { \
		if (adsz16) { ldsilddi(BIT, 16) } else { ldsilddi(BIT, 32) } \
		cpu->cc.src1 = sext ## BIT(ax0); \
		cpu->cc.src2 = sext ## BIT(ax); \
		cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
		cpu->cc.op = CC_SUB; \
		cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	} else { \
		if (adsz16) { \
			while (lreg16(1)) { \
				ldsilddi(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
				cpu->cc.src1 = sext ## BIT(ax0); \
				cpu->cc.src2 = sext ## BIT(ax); \
				cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
				cpu->cc.op = CC_SUB; \
				cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
				bool zf = get_ZF(cpu); \
				if (zf && rep == 2 || !zf && rep == 1) break; \
			} \
		} else { \
			while (lreg32(1)) { \
				ldsilddi(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
				cpu->cc.src1 = sext ## BIT(ax0); \
				cpu->cc.src2 = sext ## BIT(ax); \
				cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
				cpu->cc.op = CC_SUB; \
				cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
				bool zf = get_ZF(cpu); \
				if (zf && rep == 2 || !zf && rep == 1) break; \
			} \
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

#define indxstdi(BIT, ABIT) \
	TRY(translate ## BIT(cpu, &meml, 2, SEG_ES, lreg ## ABIT(7))); \
	ax = cpu->io_read ## BIT(cpu->io, lreg16(2)); \
	saddr ## BIT(&meml, ax); \
	sreg ## ABIT(7, lreg ## ABIT(7) + dir);

#define INS_helper(BIT) \
	TRY(check_ioperm(cpu, lreg16(2), BIT)); \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
	       if (adsz16) { indxstdi(BIT, 16) } else { indxstdi(BIT, 32) } \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		if (adsz16) { \
			while (lreg16(1)) { \
				indxstdi(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
			} \
		} else { \
			while (lreg32(1)) { \
				indxstdi(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
			} \
		} \
	}

#define INSb() INS_helper(8)
#define INS() if (opsz16) { INS_helper(16) } else { INS_helper(32) }

#define ldsioutdx(BIT, ABIT) \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	TRY(translate ## BIT(cpu, &meml, 1, curr_seg, lreg ## ABIT(6))); \
	ax = laddr ## BIT(&meml); \
	cpu->io_write ## BIT(cpu->io, lreg16(2), ax); \
	sreg ## ABIT(6, lreg ## ABIT(6) + dir);

#define OUTS_helper(BIT) \
	TRY(check_ioperm(cpu, lreg16(2), BIT)); \
	xdir ## BIT \
	u ## BIT ax; \
	if (rep == 0) { \
		if (adsz16) { ldsioutdx(BIT, 16) } else { ldsioutdx(BIT, 32) } \
	} else { \
		if (rep != 1) { \
			cpu->excno = EX_UD; \
			return false; \
		} \
		if (adsz16) { \
			while (lreg16(1)) { \
				ldsioutdx(BIT, 16) \
				sreg16(1, lreg16(1) - 1); \
			} \
		} else { \
			while (lreg32(1)) { \
				ldsioutdx(BIT, 32) \
				sreg32(1, lreg32(1) - 1); \
			} \
		} \
	}

#define OUTSb() OUTS_helper(8)
#define OUTS() if (opsz16) { OUTS_helper(16) } else { OUTS_helper(32) }

#define JCXZb(i, li, _) \
	sword d = sext8(li(i)); \
	if (adsz16) { \
		if (lreg16(1) == 0) cpu->next_ip += d; \
	} else { \
		if (lreg32(1) == 0) cpu->next_ip += d; \
	}

#define LOOPb(i, li, _) \
	sword d = sext8(li(i)); \
	if (adsz16) { \
		sreg16(1, lreg16(1) - 1); \
		if (lreg16(1)) cpu->next_ip += d; \
	} else { \
		sreg32(1, lreg32(1) - 1); \
		if (lreg32(1)) cpu->next_ip += d; \
	}

#define LOOPEb(i, li, _) \
	sword d = sext8(li(i)); \
	if (adsz16) { \
		sreg16(1, lreg16(1) - 1); \
		if (lreg16(1) && get_ZF(cpu)) cpu->next_ip += d; \
	} else { \
		sreg32(1, lreg32(1) - 1); \
		if (lreg32(1) && get_ZF(cpu)) cpu->next_ip += d; \
	}

#define LOOPNEb(i, li, _) \
	sword d = sext8(li(i)); \
	if (adsz16) { \
		sreg16(1, lreg16(1) - 1); \
		if (lreg16(1) && !get_ZF(cpu)) cpu->next_ip += d; \
	} else { \
		sreg32(1, lreg32(1) - 1); \
		if (lreg32(1) && !get_ZF(cpu)) cpu->next_ip += d; \
	}

#define COND() \
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
	}

#define JCC_common(d) \
	COND() \
	if (cond) cpu->next_ip += d;

#define SETCCb(a, la, sa) \
	COND() \
	sa(a, cond);

#define JCCb(i, li, _) \
	sword d = sext8(li(i)); \
	JCC_common(d)

#define JCCw(i, li, _) \
	sword d = sext16(li(i)); \
	JCC_common(d)

#define JCCd(i, li, _) \
	sword d = sext32(li(i)); \
	JCC_common(d)

#define JMPb(i, li, _) \
	sword d = sext8(li(i)); \
	cpu->next_ip += d;

#define JMPw(i, li, _) \
	sword d = sext16(li(i)); \
	cpu->next_ip += d;

#define JMPd(i, li, _) \
	sword d = sext32(li(i)); \
	cpu->next_ip += d;

#define JMPABSw(i, li, _) \
	cpu->next_ip = li(i);

#define JMPABSd(i, li, _) \
	cpu->next_ip = li(i);

#define JMPFAR(addr, seg) \
	if ((cpu->cr0 & 1) && !(cpu->flags & VM)) { \
		TRY(pmcall(cpu, opsz16, addr, seg, true)); \
	} else { \
	TRY(set_seg(cpu, SEG_CS, seg)); \
	cpu->next_ip = addr; \
	}

#define CALLFAR(addr, seg) \
	if ((cpu->cr0 & 1) && !(cpu->flags & VM)) { \
		TRY(pmcall(cpu, opsz16, addr, seg, false)); \
	} else { \
	OptAddr meml1, meml2; \
	uword sp = lreg32(4); \
	if (opsz16) { \
		TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask)); \
		TRY(translate16(cpu, &meml2, 2, SEG_SS, (sp - 4) & sp_mask)); \
		set_sp(sp - 4, sp_mask); \
		saddr16(&meml1, cpu->seg[SEG_CS].sel); \
		saddr16(&meml2, cpu->next_ip); \
	} else { \
		TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask)); \
		TRY(translate32(cpu, &meml2, 2, SEG_SS, (sp - 8) & sp_mask)); \
		set_sp(sp - 8, sp_mask); \
		saddr32(&meml1, cpu->seg[SEG_CS].sel); \
		saddr32(&meml2, cpu->next_ip); \
	} \
	TRY(set_seg(cpu, SEG_CS, seg)); \
	cpu->next_ip = addr; \
	}

#define CALLw(i, li, _) \
	sword d = sext16(li(i)); \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml, 2, SEG_SS, (sp - 2) & sp_mask)); \
	set_sp(sp - 2, sp_mask); \
	saddr16(&meml, cpu->next_ip); \
	cpu->next_ip += d;

#define CALLd(i, li, _) \
	sword d = sext32(li(i)); \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, (sp - 4) & sp_mask)); \
	set_sp(sp - 4, sp_mask); \
	saddr32(&meml, cpu->next_ip); \
	cpu->next_ip += d;

#define CALLABSw(i, li, _) \
	uword nip = li(i); \
	uword sp = lreg32(4); \
	TRY(translate16(cpu, &meml, 2, SEG_SS, (sp - 2) & sp_mask)); \
	set_sp(sp - 2, sp_mask); \
	saddr16(&meml, cpu->next_ip); \
	cpu->next_ip = nip;

#define CALLABSd(i, li, _) \
	uword nip = li(i); \
	uword sp = lreg32(4); \
	TRY(translate32(cpu, &meml, 2, SEG_SS, (sp - 4) & sp_mask)); \
	set_sp(sp - 4, sp_mask); \
	saddr32(&meml, cpu->next_ip); \
	cpu->next_ip = nip;

#define RETw(i, li, _) \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 2 + li(i), sp_mask); \
		cpu->next_ip = laddr16(&meml); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate32(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 4 + li(i), sp_mask); \
		cpu->next_ip = laddr32(&meml); \
	}

#define RET() \
	if (opsz16) { \
		uword sp = lreg32(4); \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 2, sp_mask); \
		cpu->next_ip = laddr16(&meml); \
	} else { \
		uword sp = lreg32(4); \
		TRY(translate32(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 4, sp_mask); \
		cpu->next_ip = laddr32(&meml); \
	}

static bool enter_helper(CPUI386 *cpu, bool opsz16, uword sp_mask,
			 int level, int allocsz)
{
	assert (level != 0);
	uword temp;
	OptAddr meml1;

	uword sp = lreg32(4);
	if (opsz16) {
		TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask));
		set_sp(sp - 2, sp_mask);
		saddr16(&meml1, lreg16(5));
		temp = lreg16(4);
	} else {
		TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask));
		set_sp(sp - 4, sp_mask);
		saddr32(&meml1, lreg32(5));
		temp = lreg32(4);
	}

	for (int i = 0; i < level - 1; i++) {
		if (opsz16) {
			if (sp_mask == 0xffff) {
				sreg16(5, lreg16(5) - 2);
			} else {
				sreg32(5, lreg32(5) - 2);
			}
			TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask));
			set_sp(sp - 2, sp_mask);
			saddr16(&meml1, lreg16(5));
		} else {
			if (sp_mask == 0xffff) {
				sreg16(5, lreg16(5) - 4);
			} else {
				sreg32(5, lreg32(5) - 4);
			}
			TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask));
			set_sp(sp - 4, sp_mask);
			saddr32(&meml1, lreg32(5));
		}
	}

	if (opsz16) {
		TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask));
		set_sp(sp - 2 - allocsz, sp_mask);
		saddr16(&meml1, temp);
		sreg16(5, temp);
	} else {
		TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask));
		set_sp(sp - 4 - allocsz, sp_mask);
		saddr32(&meml1, temp);
		sreg32(5, temp);
	}
}

#define ENTER(i16, i8, l16, s16, l8, s8) \
	OptAddr meml1; \
	int level = l8(i8) % 32; \
	if (level == 0) { \
	uword sp = lreg32(4); \
	if (opsz16) { \
		TRY(translate16(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask)); \
		set_sp(sp - 2 - l16(i16), sp_mask); \
		saddr16(&meml1, lreg16(5)); \
		sreg16(5, (sp - 2) & sp_mask); \
	} else { \
		TRY(translate32(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask)); \
		set_sp(sp - 4 - l16(i16), sp_mask); \
		saddr32(&meml1, lreg32(5)); \
		sreg32(5, (sp - 4) & sp_mask); \
	} \
	} else { \
		TRY(enter_helper(cpu, opsz16, sp_mask, level, l16(i16))); \
	}

#define LEAVE() \
	uword sp = lreg32(5); \
	if (opsz16) { \
		TRY(translate16(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 2, sp_mask); \
		sreg16(5, laddr16(&meml)); \
	} else { \
		TRY(translate32(cpu, &meml, 1, SEG_SS, sp & sp_mask)); \
		set_sp(sp + 4, sp_mask); \
		sreg32(5, laddr32(&meml)); \
	}

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
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 1, curr_seg, addr + 2)); \
	u16 limit = load16(cpu, &meml1); \
	u32 base = load32(cpu, &meml2); \
	if (opsz16) base &= 0xffffff; \
	cpu->gdt.base = base; \
	cpu->gdt.limit = limit;

#define LIDT(addr) \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	OptAddr meml1, meml2; \
	TRY(translate16(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 1, curr_seg, addr + 2)); \
	u16 limit = load16(cpu, &meml1); \
	u32 base = load32(cpu, &meml2); \
	if (opsz16) base &= 0xffffff; \
	cpu->idt.base = base; \
	cpu->idt.limit = limit;

#define LLDT(a, la, sa) \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	TRY(set_seg(cpu, SEG_LDT, la(a)));

#define SLDT(a, la, sa) \
	sa(a, cpu->seg[SEG_LDT].sel);

#define LTR(a, la, sa) \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	TRY(set_seg(cpu, SEG_TR, la(a)));

#define STR(a, la, sa) \
	sa(a, cpu->seg[SEG_TR].sel);

#define MOVFD() \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	sreg32(rm, cpu->dr[reg]);

#define MOVTD() \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int rm = modrm & 7; \
	cpu->dr[reg] = lreg32(rm);

#define MOVFT() \
	TRY(fetch8(cpu, &modrm));
#define MOVTT() \
	TRY(fetch8(cpu, &modrm));

#define SMSW(addr, laddr, saddr) \
	saddr(addr, cpu->cr0 & 0xffff);

#define LMSW(addr, laddr, saddr) \
	if (cpu->cpl != 0) { \
		cpu->excno = EX_GP; \
		cpu->excerr = 0; \
		return false; \
	} \
	cpu->cr0 = (cpu->cr0 & ((~0xf) | 1)) | (laddr(addr) & 0xf);

#define LSEGd(NAME, reg, addr, lreg32, sreg32, laddr32, saddr32) \
	OptAddr meml1, meml2; \
	if (adsz16) addr = addr & 0xffff; \
	TRY(translate32(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate16(cpu, &meml2, 1, curr_seg, addr + 4)); \
	u32 r = load32(cpu, &meml1); \
	u32 s = load16(cpu, &meml2); \
	TRY(set_seg(cpu, SEG_ ## NAME, s)); \
	sreg32(reg, r);

#define LSEGw(NAME, reg, addr, lreg16, sreg16, laddr16, saddr16) \
	OptAddr meml1, meml2; \
	if (adsz16) addr = addr & 0xffff; \
	TRY(translate16(cpu, &meml1, 1, curr_seg, addr)); \
	TRY(translate16(cpu, &meml2, 1, curr_seg, addr + 2)); \
	u32 r = load16(cpu, &meml1); \
	u32 s = load16(cpu, &meml2); \
	TRY(set_seg(cpu, SEG_ ## NAME, s)); \
	sreg16(reg, r);

#define LESd(...) LSEGd(ES, __VA_ARGS__)
#define LSSd(...) LSEGd(SS, __VA_ARGS__)
#define LDSd(...) LSEGd(DS, __VA_ARGS__)
#define LFSd(...) LSEGd(FS, __VA_ARGS__)
#define LGSd(...) LSEGd(GS, __VA_ARGS__)
#define LESw(...) LSEGw(ES, __VA_ARGS__)
#define LSSw(...) LSEGw(SS, __VA_ARGS__)
#define LDSw(...) LSEGw(DS, __VA_ARGS__)
#define LFSw(...) LSEGw(FS, __VA_ARGS__)
#define LGSw(...) LSEGw(GS, __VA_ARGS__)

static bool check_ioperm(CPUI386 *cpu, int port, int bit)
{
	bool allow = true;
	if ((cpu->cr0 & 1) && (cpu->cpl > get_IOPL(cpu) || (cpu->flags & VM))) {
		allow = false;
		if (cpu->seg[SEG_TR].limit >= 103) {
			OptAddr meml;
			TRY(translate(cpu, &meml, 1, SEG_TR, 102, 2, 0));
			u32 iobase = load16(cpu, &meml);
			if (iobase + port / 8 < cpu->seg[SEG_TR].limit) {
				TRY(translate(cpu, &meml, 1, SEG_TR, iobase + port / 8, 2, 0));
				u16 perm = load16(cpu, &meml);
				int len = bit / 8;
				unsigned bit_index = port & 0x7;
				unsigned mask = (1 << len) - 1;
				if (!((perm >> bit_index) & mask))
					allow = true;
			}
		}
	}

	if (!allow) {
		cpu->excno = EX_GP;
		cpu->excerr = 0;
		return false;
	}
	return true;
}

#define INb(a, b, la, sa, lb, sb) \
	int port = lb(b); \
	TRY(check_ioperm(cpu, port, 8)); \
	sa(a, cpu->io_read8(cpu->io, port));

#define INw(a, b, la, sa, lb, sb) \
	int port = lb(b); \
	TRY(check_ioperm(cpu, port, 16)); \
	sa(a, cpu->io_read16(cpu->io, port));

#define INd(a, b, la, sa, lb, sb) \
	int port = lb(b); \
	TRY(check_ioperm(cpu, port, 32)); \
	sa(a, cpu->io_read32(cpu->io, port));

#define OUTb(a, b, la, sa, lb, sb) \
	int port = la(a); \
	TRY(check_ioperm(cpu, port, 8)); \
	cpu->io_write8(cpu->io, port, lb(b));

#define OUTw(a, b, la, sa, lb, sb) \
	int port = la(a); \
	TRY(check_ioperm(cpu, port, 16)); \
	cpu->io_write16(cpu->io, port, lb(b));

#define OUTd(a, b, la, sa, lb, sb) \
	int port = la(a); \
	TRY(check_ioperm(cpu, port, 32)); \
	cpu->io_write32(cpu->io, port, lb(b));

#define CLTS() \
	cpu->cr0 &= ~(1 << 3);

#define ESC() \
	if (cpu->cr0 & 0xc) { \
		cpu->excno = EX_NM; \
		return false; \
	} else { \
		TRY(fetch8(cpu, &modrm)); \
		int mod = modrm >> 6; \
		int rm = modrm & 7; \
		int op = b1 - 0xd8; \
		int group = (modrm >> 3) & 7; \
		if (mod != 3) { \
			TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
			if (cpu->fpu) { \
				TRY(fpu_exec2(cpu->fpu, cpu, opsz16, op, group, curr_seg, addr)); \
			} \
		} else { \
			int reg = modrm & 7; \
			if (cpu->fpu) { \
				TRY(fpu_exec1(cpu->fpu, cpu, op, group, reg)); \
			} \
		} \
	}

#define WAIT() \
	if ((cpu->cr0 & 0xa) == 0xa) { \
		cpu->excno = EX_NM; \
		return false; \
	}

// ...
#define AAD(i, li, _) \
	u8 al = lreg8(0); \
	u8 ah = lreg8(4); \
	u8 imm = li(i); \
	u8 res = al + ah * imm; \
	sreg8(0, res); \
	sreg8(4, 0); \
	cpu->flags &= ~(OF | AF | CF); /* undocumented */ \
	cpu->cc.dst = sext8(res); \
	cpu->cc.mask = ZF | SF | PF;

#define AAM(i, li, _) \
	u8 al = lreg8(0); \
	u8 imm = li(i); \
	u8 res = al % imm; \
	sreg8(4, al / imm); \
	sreg8(0, res); \
	cpu->flags &= ~(OF | AF | CF); /* undocumented */ \
	cpu->cc.dst = sext8(res); \
	cpu->cc.mask = ZF | SF | PF;

#define SALC() \
	if (get_CF(cpu)) sreg8(0, 0xff); else sreg8(0, 0x00);

#define XLAT() \
	if (curr_seg == -1) curr_seg = SEG_DS; \
	if (adsz16) { \
		addr = lreg16(3) + lreg8(0); \
		addr &= 0xffff; \
		TRY(translate8(cpu, &meml, 1, curr_seg, addr)); \
		sreg8(0, laddr8(&meml)); \
	} else { \
		addr = lreg32(3) + lreg8(0); \
		TRY(translate8(cpu, &meml, 1, curr_seg, addr)); \
		sreg8(0, laddr8(&meml)); \
	}

#define DAA() \
	u8 al = lreg8(0); \
	int cf = get_CF(cpu); \
	cpu->flags &= ~CF; \
	if ((al & 0xf) > 9 || get_AF(cpu)) { \
		sreg8(0, al + 6); \
		if (cf || al > 0xff - 6) cpu->flags |= CF; \
		cpu->flags |= AF; \
	} else { \
		cpu->flags &= ~AF; \
	} \
	if (al > 0x99 || cf) { \
		sreg8(0, lreg8(0) + 0x60); \
		cpu->flags |= CF; \
	} \
	cpu->cc.dst = sext8(lreg8(0)); \
	cpu->cc.mask = ZF | SF | PF;

#define DAS() \
	u8 al = lreg8(0); \
	int cf = get_CF(cpu); \
	cpu->flags &= ~CF; \
	if ((al & 0xf) > 9 || get_AF(cpu)) { \
		sreg8(0, al - 6); \
		if (cf || al < 6) cpu->flags |= CF; \
		cpu->flags |= AF; \
	} else { \
		cpu->flags &= ~AF; \
	} \
	if (al > 0x99 || cf) { \
		sreg8(0, lreg8(0) - 0x60); \
		cpu->flags |= CF; \
	} \
	cpu->cc.dst = sext8(lreg8(0)); \
	cpu->cc.mask = ZF | SF | PF;

#define AAA() \
	if ((lreg8(0) & 0xf) > 9 || get_AF(cpu)) { \
		sreg16(0, lreg16(0) + 0x106); \
		cpu->flags |= AF | CF; \
	} else { \
		cpu->flags &= ~(AF | CF); \
	} \
	cpu->cc.mask = ZF | SF | PF; \
	sreg8(0, lreg8(0) & 0xf);

#define AAS() \
	if ((lreg8(0) & 0xf) > 9 || get_AF(cpu)) { \
		sreg16(0, lreg16(0) - 6); \
		sreg8(4, lreg8(4) - 1); \
		cpu->flags |= AF | CF; \
	} else { \
		cpu->flags &= ~(AF | CF); \
	} \
	cpu->cc.mask = ZF | SF | PF; \
	sreg8(0, lreg8(0) & 0xf);

static bool larsl_helper(CPUI386 *cpu, int sel, uword *ar, uword *sl, int *zf)
{
	if (!(cpu->cr0 & 1)) {
		cpu->excno = EX_UD;
		return false;
	}

	uword off = sel & ~0x7;
	uword limit;
	if (sel & 0x4) {
		limit = cpu->seg[SEG_LDT].limit;
	} else {
		limit = cpu->gdt.limit;
	}
	if (off > limit) {
		*zf = 0;
		return true;
	}

	uword w1, w2;
	TRY(read_desc(cpu, sel, &w1, &w2));

	int dpl = (w2 >> 13) & 0x3;
	if (((w2 >> 11) & 0x3) != 0x3 && cpu->cpl > dpl || (sel & 0x3) > dpl) {
		*zf = 0;
		return true;
	}

	if (ar)
		*ar = w2 & 0x00ffff00;
	if (sl) {
		if (w2 & 0x00800000)
			*sl = ((w1 & 0xffff) << 12) | 0xfff;
		else
			*sl = w1 & 0xffff;
	}
	*zf = 1;
	return true;
}

static bool verrw_helper(CPUI386 *cpu, int sel, int wr, int *zf)
{
	if (!(cpu->cr0 & 1)) {
		cpu->excno = EX_UD;
		return false;
	}

	uword off = sel & ~0x7;
	uword limit;
	if (sel & 0x4) {
		limit = cpu->seg[SEG_LDT].limit;
	} else {
		limit = cpu->gdt.limit;
	}
	if (off > limit) {
		*zf = 0;
		return true;
	}

	uword w1, w2;
	TRY(read_desc(cpu, sel, &w1, &w2));

	int dpl = (w2 >> 13) & 0x3;
	if (((w2 >> 12) & 0x1) == 0 ||
	    ((w2 >> 11) & 0x1) == 0 && cpu->cpl > dpl ||
	    (sel & 0x3) > dpl) {
		*zf = 0;
		return true;
	}

	// ...
	*zf = 1;
	return true;
}

#define LARdw(a, b, la, sa, lb, sb) \
	uword res; \
	int zf; \
	TRY(larsl_helper(cpu, lb(b), &res, NULL, &zf)); \
	if (zf) { \
		sa(a, res); \
		cpu->flags |= ZF; \
	} else { \
		cpu->flags &= ~ZF; \
	} \
	cpu->cc.mask &= ~ZF;
#define LARww LARdw

#define LSLdw(a, b, la, sa, lb, sb) \
	uword res; \
	int zf; \
	TRY(larsl_helper(cpu, lb(b), NULL, &res, &zf)); \
	if (zf) { \
		sa(a, res); \
		cpu->flags |= ZF; \
	} else { \
		cpu->flags &= ~ZF; \
	} \
	cpu->cc.mask &= ~ZF;
#define LSLww LSLdw

#define VERR(a, la, sa) \
	int zf; \
	TRY(verrw_helper(cpu, la(a), 0, &zf)); \
	cpu->cc.mask &= ~ZF; \
	if (zf) cpu->flags |= ZF; else cpu->flags &= ~ZF;

#define VERW(a, la, sa) \
	int zf; \
	TRY(verrw_helper(cpu, la(a), 1, &zf)); \
	cpu->cc.mask &= ~ZF; \
	if (zf) cpu->flags |= ZF; else cpu->flags &= ~ZF;

#define ARPL(a, b, la, sa, lb, sb) \
	if (!(cpu->cr0 & 1) || (cpu->flags & VM)) { \
		cpu->excno = EX_UD; \
		return false; \
	} \
	u16 dst = la(a); \
	u16 src = lb(b); \
	if ((dst & 3) < (src & 3)) { \
		cpu->flags |= ZF; \
		sa(a, ((dst & ~3) | (src & 3))); \
	} else { \
		cpu->flags &= ~ZF; \
	} \
	cpu->cc.mask &= ~ZF;

// 486...
#define CMPXCH_helper(BIT, a, b, la, sa, lb, sb) \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lreg ## BIT(0)); \
	cpu->cc.dst = sext ## BIT(cpu->cc.src1 - cpu->cc.src2); \
	cpu->cc.op = CC_SUB; \
	cpu->cc.mask = CF | PF | AF | ZF | SF | OF; \
	if (cpu->cc.dst == 0) sa(a, lb(b)); else sreg ## BIT(0, cpu->cc.src1); 

#define XADD_helper(BIT, a, b, la, sa, lb, sb) \
	u ## BIT dst = la(a); \
	cpu->cc.src1 = sext ## BIT(la(a)); \
	cpu->cc.src2 = sext ## BIT(lb(b)); \
	cpu->cc.dst = sext ## BIT(cpu->cc.src1 + cpu->cc.src2); \
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

#define WBINVD()

#define GvMa GvM
#define BOUND_helper(BIT, a, b, la, sa, lb, sb) \
	OptAddr meml1, meml2; \
	s ## BIT idx = la(a); \
	uword addr = lb(b); \
	TRY(translate ## BIT(cpu, &meml1, 3, curr_seg, addr)); \
	TRY(translate ## BIT(cpu, &meml2, 3, curr_seg, addr + BIT / 8)); \
	s ## BIT lo = load ## BIT(cpu, &meml1); \
	s ## BIT hi = load ## BIT(cpu, &meml2); \
	if (idx < lo || idx > hi) { \
		cpu->excno = EX_BR; \
		return false; \
	}
#define BOUNDw(...) BOUND_helper(16, __VA_ARGS__)
#define BOUNDd(...) BOUND_helper(32, __VA_ARGS__)

#define UD0() \
	cpu->excno = EX_UD; \
	return false;

#define CPUID() \
	switch (REGi(0)) { \
	case 0: \
		REGi(0) = 1; \
		REGi(3) = 0x594e4954; \
		REGi(2) = 0x20363833; \
		REGi(1) = 0x20555043; \
		break; \
	case 1: \
		REGi(0) = 0 | (0 << 4) | (4 << 8); \
		REGi(3) = 0; \
		REGi(2) = 0x101; \
		REGi(1) = 0; \
		break; \
	default: \
		REGi(0) = 0; \
		REGi(3) = 0; \
		REGi(2) = 0; \
		REGi(1) = 0; \
		break; \
	}

#include <time.h>
static uint64_t get_nticks()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000000000ull +
	    (uint64_t) ts.tv_nsec);
}

#define RDTSC() \
	uint64_t tsc = get_nticks(); \
	REGi(0) = tsc; \
	REGi(2) = tsc >> 32;

#define Mq Ms
#define CMPXCH8B(addr) \
	OptAddr meml1, meml2; \
	TRY(translate32(cpu, &meml1, 3, curr_seg, addr)); \
	TRY(translate32(cpu, &meml2, 3, curr_seg, addr + 4)); \
	uword lo = load32(cpu, &meml1); \
	uword hi = load32(cpu, &meml2); \
	if (REGi(0) == lo && REGi(2) == hi) { \
		cpu->flags |= ZF; \
		store32(cpu, &meml1, REGi(3)); \
		store32(cpu, &meml2, REGi(1)); \
	} else { \
		cpu->flags &= ~ZF; \
		REGi(0) = lo; \
		REGi(2) = hi; \
	} \
	cpu->cc.mask &= ~ZF;

#define CMOVw(a, b, la, sa, lb, sb) \
	COND() \
	if (cond) sa(a, lb(b));

#define CMOVd(a, b, la, sa, lb, sb) \
	COND() \
	if (cond) sa(a, lb(b));

static bool pmcall(CPUI386 *cpu, bool opsz16, uword addr, int sel, bool isjmp);
static bool pmret(CPUI386 *cpu, bool opsz16, int off, bool isiret);

static bool verbose;

static bool cpu_exec1(CPUI386 *cpu, int stepcount)
{
#define eswitch(b) switch(b)
#define ecase(a)   case a
#define ebreak     break
#define edefault   default
#define default_ud cpu_debug(cpu); cpu->excno = EX_UD; return false
#undef CX
#define CX(_1) case _1:

	u8 b1;
	u8 modrm;
	OptAddr meml;
	uword addr;
	for (; stepcount > 0; stepcount--) {
	bool code16 = !(cpu->seg[SEG_CS].flags & SEG_D_BIT);
	uword sp_mask =  cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;

	if (code16) cpu->next_ip &= 0xffff;
	cpu->ip = cpu->next_ip;
	TRY(fetch8(cpu, &b1));
	cpu->cycle++;

	if (verbose) {
		cpu_debug(cpu);
	}

	// prefix
	bool opsz16 = code16;
	bool adsz16 = code16;
	int rep = 0;
	bool lock = false;
	int curr_seg = -1;
	for (;;) {
#define HANDLE_PREFIX(C, STMT) \
		if (b1 == C) { \
			STMT; \
			TRY(fetch8(cpu, &b1)); \
			continue; \
		}
		HANDLE_PREFIX(0x26, curr_seg = SEG_ES)
		HANDLE_PREFIX(0x2e, curr_seg = SEG_CS)
		HANDLE_PREFIX(0x36, curr_seg = SEG_SS)
		HANDLE_PREFIX(0x3e, curr_seg = SEG_DS)
		HANDLE_PREFIX(0x64, curr_seg = SEG_FS)
		HANDLE_PREFIX(0x65, curr_seg = SEG_GS)
		HANDLE_PREFIX(0x66, opsz16 = !code16)
		HANDLE_PREFIX(0x67, adsz16 = !code16)
		HANDLE_PREFIX(0xf3, rep = 1) // REP
		HANDLE_PREFIX(0xf2, rep = 2) // REPNE
		HANDLE_PREFIX(0xf0, lock = true)
#undef HANDLE_PREFIX
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

	ecase(0x80): ecase(0x82): { // G1b
		TRY(peek8(cpu, &modrm));
		switch((modrm >> 3) & 7) {
#undef IG1b
#define IG1b(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG1b
#define IG1b(...)
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
		default: default_ud;
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
			default: default_ud;
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
			default: default_ud;
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
			default: default_ud;
			}
			ebreak;
		}

		case 0xc7: { // G9
			TRY(peek8(cpu, &modrm));
			switch((modrm >> 3) & 7) {
#undef IG9
#define IG9(_case, _rm, _rwm, _op) _case { _rm(_rwm, _op); ebreak; }
#include "i386ins.def"
#undef IG9
#define IG9(...)
			default: default_ud;
			}
			ebreak;
		}
		default: default_ud;
		}
		ebreak;
	}

	edefault: default_ud;
	}
	}
	return true;
}

static bool pmcall(CPUI386 *cpu, bool opsz16, uword addr, int sel, bool isjmp)
{
	sel = sel & 0xffff;
	uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;

	if ((sel & ~0x3) == 0) {
		cpu->excno = EX_GP;
		cpu->excerr = 0;
		return false;
	}

	uword w1, w2;
	TRY(read_desc(cpu, sel, &w1, &w2));

	int s = (w2 >> 12) & 1;
	int dpl = (w2 >> 13) & 0x3;
	int p = (w2 >> 15) & 1;
	if (!p) {
//		fprintf(stderr, "pmcall: seg not present %04x\n", sel);
		cpu->excno = EX_NP;
		cpu->excerr = sel & ~0x3;
		return false;
	}

	if (s) {
		bool code = (w2 >> 8) & 0x8;
		bool conforming = (w2 >> 8) & 0x4;
		if (!code) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}
		if (conforming) {
			// call conforming code segment
			if (dpl > cpu->cpl) {
				cpu->excno = EX_GP;
				cpu->excerr = sel & ~0x3;
				return false;
			}
			sel = (sel & 0xfffc) | cpu->cpl;
		} else {
			// call nonconforming code segment
			if ((sel & 0x3) > cpu->cpl || dpl != cpu->cpl) {
				cpu->excno = EX_GP;
				cpu->excerr = sel & ~0x3;
				return false;
			}
			sel = (sel & 0xfffc) | cpu->cpl;
		}

		if (!isjmp) {
			OptAddr meml1, meml2;
			uword sp = lreg32(4);
			if (opsz16) {
				TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 2) & sp_mask, 2, 0));
				TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 4) & sp_mask, 2, 0));
				set_sp(sp - 4, sp_mask);
				saddr16(&meml1, cpu->seg[SEG_CS].sel);
				saddr16(&meml2, cpu->next_ip);
			} else {
				TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 4) & sp_mask, 4, 0));
				TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 8) & sp_mask, 4, 0));
				set_sp(sp - 8, sp_mask);
				saddr32(&meml1, cpu->seg[SEG_CS].sel);
				saddr32(&meml2, cpu->next_ip);
			}
		}
//		if ((sel & 3) != cpu->cpl)
//			fprintf(stderr, "pmcall PVL %d => %d\n", cpu->cpl, sel & 3);
		TRY1(set_seg(cpu, SEG_CS, sel));
		cpu->next_ip = addr;
	} else {
		assert(!isjmp);
		OptAddr meml;
		int newcs = w1 >> 16;
		uword newip = (w1 & 0xffff) | (w2 & 0xffff0000);
		int gt = (w2 >> 8) & 0xf;
		int wc = w2 & 31;
		assert(gt == 4 || gt == 12); // call gate

		if (dpl < cpu->cpl || dpl < (sel & 3)) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}

		// examine code segment selector in call gate descriptor
		if ((newcs & ~0x3) == 0) {
			cpu->excno = EX_GP;
			cpu->excerr = 0;
			return false;
		}
		uword neww2;
		TRY(read_desc(cpu, newcs, NULL, &neww2));

		if (((neww2 >> 11) & 0x3) != 0x3) {
			// not code segment
			cpu->excno = EX_GP;
			cpu->excerr = newcs & ~0x3;
			return false;
		}

		int newdpl = (neww2 >> 13) & 0x3;
		int newp = (neww2 >> 15) & 1;
		if (!newp) {
			cpu->excno = EX_NP;
			cpu->excerr = newcs & ~0x3;
			return false;
		}

		if (newdpl > cpu->cpl) {
			cpu->excno = EX_GP;
			cpu->excerr = newcs & ~0x3;
			return false;
		}

		bool conforming = (neww2 >> 8) & 0x4;
		bool gate16 = (gt == 4);
		if (!conforming && newdpl < cpu->cpl) {
			// more privilege
			OptAddr msp0, mss0;
			uword oldss = cpu->seg[SEG_SS].sel;
			uword oldsp = cpu->gpr[4];
			uword params[31];
			uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;

			if (!gate16) {
				for (int i = 0; i < wc; i++) {
					OptAddr meml;
					TRY(translate(cpu, &meml, 1, SEG_SS, (oldsp + 4 * i) & sp_mask, 4, 0));
					params[i] = laddr32(&meml);
				}
			} else {
				for (int i = 0; i < wc; i++) {
					OptAddr meml;
					TRY(translate(cpu, &meml, 1, SEG_SS, (oldsp + 2 * i) & sp_mask, 2, 0));
					params[i] = laddr16(&meml);
				}
			}

			if (!(cpu->seg[SEG_TR].flags & 0x8)) {
				TRY(translate(cpu, &msp0, 1, SEG_TR, 2 + 4 * newdpl, 2, 0));
				TRY(translate(cpu, &mss0, 1, SEG_TR, 4 + 4 * newdpl, 2, 0));
				// TODO: Check SS...
				cpu->gpr[4] = load16(cpu, &msp0);
				TRY(set_seg(cpu, SEG_SS, load16(cpu, &mss0)));
			} else {
				TRY(translate(cpu, &msp0, 1, SEG_TR, 4 + 8 * newdpl, 4, 0));
				TRY(translate(cpu, &mss0, 1, SEG_TR, 8 + 8 * newdpl, 4, 0));
				// TODO: Check SS...
				cpu->gpr[4] = load32(cpu, &msp0);
				TRY(set_seg(cpu, SEG_SS, load32(cpu, &mss0)));
			}
			sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;

			if (!gate16) {
				OptAddr meml1, meml2, meml3, meml4;
				uword sp = lreg32(4);
				TRY1(translate(cpu, &meml1, 2, SEG_SS, (sp - 4 * 1) & sp_mask, 4, 0));
				TRY1(translate(cpu, &meml2, 2, SEG_SS, (sp - 4 * 2) & sp_mask, 4, 0));
				TRY1(translate(cpu, &meml3, 2, SEG_SS, (sp - 4 * (3 + wc)) & sp_mask, 4, 0));
				TRY1(translate(cpu, &meml4, 2, SEG_SS, (sp - 4 * (4 + wc)) & sp_mask, 4, 0));

				for (int i = 0; i < wc; i++) {
					OptAddr meml;
					TRY1(translate(cpu, &meml, 2, SEG_SS, (sp - 4 * (2 + wc - i)) & sp_mask, 4, 0));
					saddr32(&meml, params[i]);
				}

				saddr32(&meml1, oldss);
				saddr32(&meml2, oldsp);
				saddr32(&meml3, cpu->seg[SEG_CS].sel);
				saddr32(&meml4, cpu->next_ip);
				set_sp(sp - 4 * (4 + wc), sp_mask);
			} else {
				OptAddr meml1, meml2, meml3, meml4;
				uword sp = lreg32(4);
				TRY1(translate(cpu, &meml1, 2, SEG_SS, (sp - 2 * 1) & sp_mask, 2, 0));
				TRY1(translate(cpu, &meml2, 2, SEG_SS, (sp - 2 * 2) & sp_mask, 2, 0));
				TRY1(translate(cpu, &meml3, 2, SEG_SS, (sp - 2 * (3 + wc)) & sp_mask, 2, 0));
				TRY1(translate(cpu, &meml4, 2, SEG_SS, (sp - 2 * (4 + wc)) & sp_mask, 2, 0));

				for (int i = 0; i < wc; i++) {
					OptAddr meml;
					TRY1(translate(cpu, &meml, 2, SEG_SS, (sp - 2 * (2 + wc - i)) & sp_mask, 2, 0));
					saddr16(&meml, params[i]);
				}

				saddr16(&meml1, oldss);
				saddr16(&meml2, oldsp);
				saddr16(&meml3, cpu->seg[SEG_CS].sel);
				saddr16(&meml4, cpu->next_ip);
				set_sp(sp - 2 * (4 + wc), sp_mask);
			}
			newcs = (newcs & 0xfffc) | newdpl;
		} else {
			// same privilege
			OptAddr meml1, meml2;
			uword sp = lreg32(4);
			uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
			if (gate16) {
				TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 2 * 1) & sp_mask, 2, 0));
				TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 2 * 2) & sp_mask, 2, 0));
				saddr16(&meml1, cpu->seg[SEG_CS].sel);
				saddr16(&meml2, cpu->next_ip);
				set_sp(sp - 2 * 2, sp_mask);
			} else {
				TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 4 * 1) & sp_mask, 4, 0));
				TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 4 * 2) & sp_mask, 4, 0));
				saddr32(&meml1, cpu->seg[SEG_CS].sel);
				saddr32(&meml2, cpu->next_ip);
				set_sp(sp - 4 * 2, sp_mask);
			}
			newcs = (newcs & 0xfffc) | cpu->cpl;
		}

		TRY1(set_seg(cpu, SEG_CS, newcs));

		cpu->next_ip = newip;
	}
	return true;
}

// 0: exception
// 1: intra PVL
// 2: inter PVL
// 3: from v8086
static int __call_isr_check_cs(CPUI386 *cpu, int sel, int ext, int *csdpl)
{
	sel = sel & 0xffff;
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
	if ((sel & ~0x3) == 0 || off > limit) {
		cpu->excno = EX_GP;
		cpu->excerr = ext;
		return 0;
	}

	TRY1(translate_laddr(cpu, &meml, 1, base + off + 4, 4, 0));
	uword w2 = load32(cpu, &meml);
	int s = (w2 >> 12) & 1;
	bool code = (w2 >> 8) & 0x8;
	bool conforming = (w2 >> 8) & 0x4;
	int dpl = (w2 >> 13) & 0x3;
	int p = (w2 >> 15) & 1;
	*csdpl = dpl;
	if (!s || !code || dpl > cpu->cpl) {
		cpu->excno = EX_GP;
		cpu->excerr = (sel & ~0x3) | ext;
		return 0;
	}

	if (!p) {
		cpu->excno = EX_NP;
		cpu->excerr = sel & ~0x3;
		return 0;
	}

	if (!conforming && dpl < cpu->cpl) {
		if (!(cpu->flags & VM)) {
			return 2;
		} else {
			if (dpl != 0) {
				cpu->excno = EX_GP;
				cpu->excerr = (sel & ~0x3) | ext;
				fprintf(stderr, "__call_isr_check_cs fail1: %d %d %d\n", conforming, dpl, cpu->cpl);
				return 0;
			} else {
				return 3;
			}
		}
	} else {
		if (cpu->flags & VM) {
			cpu->excno = EX_GP;
			cpu->excerr = (sel & ~0x3) | ext;
			return 0;
		} else {
			if (conforming || dpl == cpu->cpl) {
				return 1;
			} else {
				cpu->excno = EX_GP;
				cpu->excerr = (sel & ~0x3) | ext;
				fprintf(stderr, "__call_isr_check_cs fail2: %d %d %d\n", conforming, dpl, cpu->cpl);
				return 0;
			}
		}
	}
}

static bool call_isr(CPUI386 *cpu, int no, bool pusherr, int ext)
{
	if (!(cpu->cr0 & 1)) {
		/* REAL-ADDRESS-MODE */
		uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
		OptAddr meml;
		uword base = cpu->idt.base;
		int off = no * 4;
		TRY1(translate_laddr(cpu, &meml, 1, base + off, 4, 0));
		uword w1 = load32(cpu, &meml);
		int newcs = w1 >> 16;
		uword newip = w1 & 0xffff;

		OptAddr meml1, meml2, meml3;
		uword sp = lreg32(4);
		TRY1(translate(cpu, &meml1, 2, SEG_SS, (sp - 2 * 1) & sp_mask, 2, 0));
		TRY1(translate(cpu, &meml2, 2, SEG_SS, (sp - 2 * 2) & sp_mask, 2, 0));
		TRY1(translate(cpu, &meml3, 2, SEG_SS, (sp - 2 * 3) & sp_mask, 2, 0));
		refresh_flags(cpu);
		cpu->cc.mask = 0;
		saddr16(&meml1, cpu->flags);
		saddr16(&meml2, cpu->seg[SEG_CS].sel);
		saddr16(&meml3, cpu->ip);
		sreg32(4, (sp - 2 * 3) & sp_mask);

		TRY1(set_seg(cpu, SEG_CS, newcs));
		cpu->next_ip = newip;
		cpu->ip = newip;
		cpu->flags &= ~(IF|TF);
		return true;
	}

	/* PROTECTED-MODE */
	OptAddr meml;
	uword base = cpu->idt.base;
	int off = no << 3;
	if (off + 7 > cpu->idt.limit) {
		cpu->excno = EX_GP;
		cpu->excerr = off | 2 | ext;
		fprintf(stderr, "call_isr error0 %d %d\n", off, cpu->idt.limit);
		return false;
	}

	TRY1(translate_laddr(cpu, &meml, 1, base + off, 4, 0));
	uword w1 = load32(cpu, &meml);
	TRY1(translate_laddr(cpu, &meml, 1, base + off + 4, 4, 0));
	uword w2 = load32(cpu, &meml);

	int gt = (w2 >> 8) & 0xf;
	if (gt != 6 && gt != 7 && gt != 0xe && gt != 0xf && gt != 5) {
		cpu->excno = EX_GP;
		cpu->excerr = off | 2 | ext;
		fprintf(stderr, "call_isr error1 gt=%d\n", gt);
		return false;
	}

	int dpl = (w2 >> 13) & 0x3;
	if (!ext && dpl < cpu->cpl) {
		cpu->excno = EX_GP;
		cpu->excerr = off | 2;
		return false;
	}

	int p = (w2 >> 15) & 1;
	if (!p) {
		cpu->excno = EX_NP;
		cpu->excerr = off | 2 | ext;
		fprintf(stderr, "call_isr error3\n");
		return false;
	}

	/* task gate is not supported */
	assert(gt != 5);

	/* TRAP-OR-INTERRUPT-GATE */
	int newcs = w1 >> 16;
	uword newip = (w1 & 0xffff) | (w2 & 0xffff0000);
	bool gate16 = gt == 6 || gt == 7;

	int csdpl;
	switch(__call_isr_check_cs(cpu, newcs, ext, &csdpl)) {
	case 0: {
		return false;
	}
	case 1: /* intra PVL */ {
		OptAddr meml1, meml2, meml3, meml4;
		uword sp = lreg32(4);
		uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
		if (gate16) {
			TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 2 * 1) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 2 * 2) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml3, 2, SEG_SS, (sp - 2 * 3) & sp_mask, 2, 0));
			if (pusherr) {
				TRY(translate(cpu, &meml4, 2, SEG_SS, (sp - 2 * 4) & sp_mask, 2, 0));
			}

			refresh_flags(cpu);
			cpu->cc.mask = 0;
			saddr16(&meml1, cpu->flags);

			saddr16(&meml2, cpu->seg[SEG_CS].sel);
			saddr16(&meml3, cpu->ip);
			if (pusherr) {
				saddr32(&meml4, cpu->excerr);
				set_sp(sp - 2 * 4, sp_mask);
			} else {
				set_sp(sp - 2 * 3, sp_mask);
			}
		} else {
			TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 4 * 1) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 4 * 2) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml3, 2, SEG_SS, (sp - 4 * 3) & sp_mask, 4, 0));
			if (pusherr) {
				TRY(translate(cpu, &meml4, 2, SEG_SS, (sp - 4 * 4) & sp_mask, 4, 0));
			}

			refresh_flags(cpu);
			cpu->cc.mask = 0;
			saddr32(&meml1, cpu->flags);

			saddr32(&meml2, cpu->seg[SEG_CS].sel);
			saddr32(&meml3, cpu->ip);
			if (pusherr) {
				saddr32(&meml4, cpu->excerr);
				set_sp(sp - 4 * 4, sp_mask);
			} else {
				set_sp(sp - 4 * 3, sp_mask);
			}
		}
		newcs = (newcs & (~3)) | cpu->cpl;
		break;
	}
	case 2: /* inter PVL */ {
//		fprintf(stderr, "call_isr %d %x PVL %d => %d\n", no, no, cpu->cpl, csdpl);
		OptAddr meml;
		OptAddr msp0, mss0;
		int newpl = csdpl;
		uword oldss = cpu->seg[SEG_SS].sel;
		uword oldsp = cpu->gpr[4];
		uword newss, newsp;
		if (cpu->seg[SEG_TR].flags & 0x8) {
			TRY(translate(cpu, &msp0, 1, SEG_TR, 4 + 8 * newpl, 4, 0));
			TRY(translate(cpu, &mss0, 1, SEG_TR, 8 + 8 * newpl, 4, 0));
			newsp = load32(cpu, &msp0);
			newss = load32(cpu, &mss0) & 0xffff;
		} else {
			TRY(translate(cpu, &msp0, 1, SEG_TR, 2 + 4 * newpl, 2, 0));
			TRY(translate(cpu, &mss0, 1, SEG_TR, 4 + 4 * newpl, 2, 0));
			newsp = load16(cpu, &msp0);
			newss = load16(cpu, &mss0);
		}

		cpu->gpr[4] = newsp;
		TRY(set_seg(cpu, SEG_SS, newss));
		uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
		OptAddr meml1, meml2, meml3, meml4, meml5, meml6;
		uword sp = lreg32(4);
		if (gate16) {
			TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 2 * 1) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 2 * 2) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml3, 2, SEG_SS, (sp - 2 * 3) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml4, 2, SEG_SS, (sp - 2 * 4) & sp_mask, 2, 0));
			TRY(translate(cpu, &meml5, 2, SEG_SS, (sp - 2 * 5) & sp_mask, 2, 0));
			if (pusherr) {
				TRY(translate(cpu, &meml6, 2, SEG_SS, (sp - 2 * 6) & sp_mask, 2, 0));
			}
			saddr16(&meml1, oldss);
			saddr16(&meml2, oldsp);

			refresh_flags(cpu);
			cpu->cc.mask = 0;
			saddr16(&meml3, cpu->flags);

			saddr16(&meml4, cpu->seg[SEG_CS].sel);
			saddr16(&meml5, cpu->ip);
			if (pusherr) {
				saddr16(&meml6, cpu->excerr);
				set_sp(sp - 2 * 6, sp_mask);
			} else {
				set_sp(sp - 2 * 5, sp_mask);
			}
		} else {
			TRY(translate(cpu, &meml1, 2, SEG_SS, (sp - 4 * 1) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml2, 2, SEG_SS, (sp - 4 * 2) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml3, 2, SEG_SS, (sp - 4 * 3) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml4, 2, SEG_SS, (sp - 4 * 4) & sp_mask, 4, 0));
			TRY(translate(cpu, &meml5, 2, SEG_SS, (sp - 4 * 5) & sp_mask, 4, 0));
			if (pusherr) {
				TRY(translate(cpu, &meml6, 2, SEG_SS, (sp - 4 * 6) & sp_mask, 4, 0));
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
		}
		newcs = (newcs & (~3)) | newpl;
		break;
	}
	case 3: /* from v8086 */ {
//		fprintf(stderr, "int from v8086\n");
		assert(csdpl == 0);
		assert(!gate16);
//		fprintf(stderr, "call_isr %d %x PVL %d => 0\n", no, no, cpu->cpl, csdpl);
		OptAddr meml;
		OptAddr msp0, mss0;
		int newpl = 0;
		uword oldss = cpu->seg[SEG_SS].sel;
		uword oldsp = cpu->gpr[4];
		uword newss, newsp;
		assert(cpu->seg[SEG_TR].flags & 0x8);
		TRY(translate(cpu, &msp0, 1, SEG_TR, 4 + 8 * newpl, 4, 0));
		TRY(translate(cpu, &mss0, 1, SEG_TR, 8 + 8 * newpl, 4, 0));
		newsp = load32(cpu, &msp0);
		newss = load32(cpu, &mss0) & 0xffff;
		uword oldflags = cpu->flags;
		cpu->flags &= ~VM;
		cpu->gpr[4] = newsp;
		if (!set_seg(cpu, SEG_SS, newss)) {
			cpu->flags = oldflags;
			cpu->gpr[4] = oldsp;
			return false;
		}

		uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
		OptAddr memlg, memlf, memld, memle;
		OptAddr meml1, meml2, meml3, meml4, meml5, meml6;
		uword sp = lreg32(4);
		TRY1(translate(cpu, &memlg, 2, SEG_SS, (sp - 4 * 1) & sp_mask, 4, 0));
		TRY1(translate(cpu, &memlf, 2, SEG_SS, (sp - 4 * 2) & sp_mask, 4, 0));
		TRY1(translate(cpu, &memld, 2, SEG_SS, (sp - 4 * 3) & sp_mask, 4, 0));
		TRY1(translate(cpu, &memle, 2, SEG_SS, (sp - 4 * 4) & sp_mask, 4, 0));
		TRY1(translate(cpu, &meml1, 2, SEG_SS, (sp - 4 * 5) & sp_mask, 4, 0));
		TRY1(translate(cpu, &meml2, 2, SEG_SS, (sp - 4 * 6) & sp_mask, 4, 0));
		TRY1(translate(cpu, &meml3, 2, SEG_SS, (sp - 4 * 7) & sp_mask, 4, 0));
		TRY1(translate(cpu, &meml4, 2, SEG_SS, (sp - 4 * 8) & sp_mask, 4, 0));
		TRY1(translate(cpu, &meml5, 2, SEG_SS, (sp - 4 * 9) & sp_mask, 4, 0));
		if (pusherr) {
			TRY(translate(cpu, &meml6, 2, SEG_SS, (sp - 4 * 10) & sp_mask, 4, 0));
		}
		saddr32(&memlg, cpu->seg[SEG_GS].sel);
		saddr32(&memlf, cpu->seg[SEG_FS].sel);
		saddr32(&memld, cpu->seg[SEG_DS].sel);
		saddr32(&memle, cpu->seg[SEG_ES].sel);
		saddr32(&meml1, oldss);
		saddr32(&meml2, oldsp);

		refresh_flags(cpu);
		cpu->cc.mask = 0;
		saddr32(&meml3, cpu->flags | VM);

		saddr32(&meml4, cpu->seg[SEG_CS].sel);
		saddr32(&meml5, cpu->ip);
		if (pusherr) {
			saddr32(&meml6, cpu->excerr);
			set_sp(sp - 4 * 10, sp_mask);
		} else {
			set_sp(sp - 4 * 9, sp_mask);
		}

		newcs = (newcs & (~3)) | newpl;
		TRY1(set_seg(cpu, SEG_DS, 0));
		TRY1(set_seg(cpu, SEG_ES, 0));
		TRY1(set_seg(cpu, SEG_FS, 0));
		TRY1(set_seg(cpu, SEG_GS, 0));
		cpu->flags &= ~(TF | RF | NT);
		TRY1(set_seg(cpu, SEG_CS, newcs));
		cpu->next_ip = newip;
		cpu->ip = newip;
		if (gt == 0x6 || gt == 0xe)
			cpu->flags &= ~IF;
		return true;
	}
	default: assert(false);
	}
	TRY1(set_seg(cpu, SEG_CS, newcs));
	cpu->next_ip = newip;
	cpu->ip = newip;
	if (gt == 0x6 || gt == 0xe)
		cpu->flags &= ~IF;
	return true;
}

static bool __pmiret_check_cs_same(CPUI386 *cpu, int sel)
{
	sel = sel & 0xffff;
	if ((sel & ~0x3) == 0) {
		cpu->excno = EX_GP;
		cpu->excerr = sel & ~0x3;
		fprintf(stderr, "__pmiret_check_cs_same: sel %04x\n", sel);
		return false;
	}
	uword w2;
	TRY(read_desc(cpu, sel, NULL, &w2));

	int s = (w2 >> 12) & 1;
	bool code = (w2 >> 8) & 0x8;
	bool conforming = (w2 >> 8) & 0x4;
	int dpl = (w2 >> 13) & 0x3;
	int p = (w2 >> 15) & 1;

	if (!s || !code) {
		cpu->excno = EX_GP;
		cpu->excerr = sel & ~0x3;
		return false;
	}

	if (!conforming) {
		if (dpl != cpu->cpl) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}
	} else {
		if (dpl > cpu->cpl) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}
	}

	if (!p) {
//		fprintf(stderr, "__pmiret_check_cs_same: seg not present %04x\n", sel);
		cpu->excno = EX_NP;
		cpu->excerr = sel & ~0x3;
		return false;
	}
	return true;
}

static bool __pmiret_check_cs_outer(CPUI386 *cpu, int sel)
{
	sel = sel & 0xffff;
	if ((sel & ~0x3) == 0) {
		cpu->excno = EX_GP;
		cpu->excerr = sel & ~0x3;
		fprintf(stderr, "__pmiret_check_cs_outer: sel %04x\n", sel);
		return false;
	}
	uword w2;
	TRY(read_desc(cpu, sel, NULL, &w2));

	int s = (w2 >> 12) & 1;
	bool code = (w2 >> 8) & 0x8;
	bool conforming = (w2 >> 8) & 0x4;
	int dpl = (w2 >> 13) & 0x3;
	int p = (w2 >> 15) & 1;
	int rpl = sel & 3;

	if (!s || !code) {
		cpu->excno = EX_GP;
		cpu->excerr = sel & ~0x3;
		return false;
	}

	if (!conforming) {
		if (dpl != rpl) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}
	} else {
		if (dpl <= cpu->cpl) {
			cpu->excno = EX_GP;
			cpu->excerr = sel & ~0x3;
			return false;
		}
	}

	if (!p) {
//		fprintf(stderr, "__pmiret_check_cs_outer: seg not present %04x\n", sel);
		cpu->excno = EX_NP;
		cpu->excerr = sel & ~0x3;
		return false;
	}
	return true;
}

static bool pmret(CPUI386 *cpu, bool opsz16, int off, bool isiret)
{
	if (isiret) {
		if ((cpu->flags & VM)) {
			cpu->excno = EX_GP;
			cpu->excerr = 0;
			return false;
		}
		if ((cpu->flags & NT)) {
			fprintf(stderr, "IRET NT\n");
			cpu_debug(cpu);
			abort();
		}
		if (opsz16)
			off += 2;
		else
			off += 4;
	}

	OptAddr meml1, meml2, meml3, meml4, meml5;
	uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
	uword sp = lreg32(4);
	uword oldflags = cpu->flags;
	uword newip;
	int newcs;
	uword newflags;
	if (opsz16) {
		/* ip */ TRY(translate(cpu, &meml1, 1, SEG_SS, sp & sp_mask, 2, 0));
		/* cs */ TRY(translate(cpu, &meml2, 1, SEG_SS, (sp + 2) & sp_mask, 2, 0));
		if (isiret) {
			/* flags */ TRY(translate(cpu, &meml3, 1, SEG_SS, (sp + 4) & sp_mask, 2, 0));
			newflags = (oldflags & 0xffff0000) | laddr16(&meml3);
		}
		newip = laddr16(&meml1);
		newcs = laddr16(&meml2);
	} else {
		/* ip */ TRY(translate(cpu, &meml1, 1, SEG_SS, sp & sp_mask, 4, 0));
		/* cs */ TRY(translate(cpu, &meml2, 1, SEG_SS, (sp + 4) & sp_mask, 4, 0));
		if (isiret) {
			/* flags */ TRY(translate(cpu, &meml3, 1, SEG_SS, (sp + 8) & sp_mask, 4, 0));
			newflags = laddr32(&meml3);
		}
		newip = laddr32(&meml1);
		newcs = laddr32(&meml2);
	}

	if (isiret) {
		uword mask = 0;
		if (cpu->cpl > 0) mask |= IOPL;
		if (get_IOPL(cpu) < cpu->cpl) mask |= IF;
		newflags = (oldflags & mask) | (newflags & ~mask);
		newflags &= EFLAGS_MASK;
		newflags |= 0x2;
	}

	if (isiret && (newflags & VM)) {
		assert(cpu->cpl == 0);
		// return to v8086
//		fprintf(stderr, "pmiret PVL %d => %d (vm) %04x:%08x\n", cpu->cpl, 3, newcs, newip);
		OptAddr meml_vmes, meml_vmds, meml_vmfs, meml_vmgs;
		assert (!opsz16);
		TRY(translate(cpu, &meml4, 1, SEG_SS, (sp + 12) & sp_mask, 4, 0));
		TRY(translate(cpu, &meml5, 1, SEG_SS, (sp + 16) & sp_mask, 4, 0));
		TRY(translate(cpu, &meml_vmes, 1, SEG_SS, (sp + 20) & sp_mask, 4, 0));
		TRY(translate(cpu, &meml_vmds, 1, SEG_SS, (sp + 24) & sp_mask, 4, 0));
		TRY(translate(cpu, &meml_vmfs, 1, SEG_SS, (sp + 28) & sp_mask, 4, 0));
		TRY(translate(cpu, &meml_vmgs, 1, SEG_SS, (sp + 32) & sp_mask, 4, 0));
		cpu->flags = newflags;
		TRY1(set_seg(cpu, SEG_CS, newcs));
		set_sp(sp + 12, sp_mask);
		cpu->next_ip = newip;
		TRY1(set_seg(cpu, SEG_SS, laddr32(&meml5)));
		TRY1(set_seg(cpu, SEG_ES, laddr32(&meml_vmes)));
		TRY1(set_seg(cpu, SEG_DS, laddr32(&meml_vmds)));
		TRY1(set_seg(cpu, SEG_FS, laddr32(&meml_vmfs)));
		TRY(set_seg(cpu, SEG_GS, laddr32(&meml_vmgs)));
		set_sp(laddr32(&meml4), 0xffffffff);
	} else {
		int rpl = newcs & 3;
		if (rpl < cpu->cpl) {
			cpu->excno = EX_GP;
			cpu->excerr = newcs & ~0x3;
			return false;
		}

		if (rpl == cpu->cpl) {
			// return to same level
			TRY(__pmiret_check_cs_same(cpu, newcs));
//			fprintf(stderr, "pmiret PVL %d => %d %04x:%08x\n", cpu->cpl, newcs & 3, newcs, newip);
			if (isiret)
				cpu->flags = newflags;
			TRY1(set_seg(cpu, SEG_CS, newcs));

			if (opsz16) {
				set_sp(sp + 4 + off, sp_mask);
			} else {
				set_sp(sp + 8 + off, sp_mask);
			}
			cpu->next_ip = newip;
		} else {
			// return to outer level
			TRY(__pmiret_check_cs_outer(cpu, newcs));
			uword newsp;
			uword newss;
//			fprintf(stderr, "pmiret PVL %d => %d %04x:%08x\n", cpu->cpl, newcs & 3, newcs, newip);
			if (opsz16) {
				/* sp */ TRY(translate(cpu, &meml4, 1, SEG_SS, (sp + 4 + off) & sp_mask, 2, 0));
				/* ss */ TRY(translate(cpu, &meml5, 1, SEG_SS, (sp + 6 + off) & sp_mask, 2, 0));
				newsp = laddr16(&meml4);
				newss = laddr16(&meml5);
			} else {
				/* sp */ TRY(translate(cpu, &meml4, 1, SEG_SS, (sp + 8 + off) & sp_mask, 4, 0));
				/* ss */ TRY(translate(cpu, &meml5, 1, SEG_SS, (sp + 12 + off) & sp_mask, 4, 0));
				newsp = laddr32(&meml4);
				newss = laddr32(&meml5);
			}

			if (isiret)
				cpu->flags = newflags;
			int oldcs = cpu->seg[SEG_CS].sel;
			int oldcpl = cpu->cpl;
			TRY1(set_seg(cpu, SEG_CS, newcs));
			TRY1(set_seg(cpu, SEG_SS, newss));
			uword newsp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
			set_sp(newsp, newsp_mask);
			cpu->next_ip = newip;
			clear_segs(cpu);
		}
	}
	if (isiret)
		cpu->cc.mask = 0;
	return true;
}

void cpui386_step(CPUI386 *cpu, int stepcount)
{
	if ((cpu->flags & IF) && cpu->intr) {
		cpu->intr = false;
		cpu->halt = false;
		int no = cpu->pic_read_irq(cpu->pic);
		cpu->ip = cpu->next_ip;
		TRY1(call_isr(cpu, no, false, 1));
	}

	if (cpu->halt) {
		usleep(1);
		return;
	}

	if (!cpu_exec1(cpu, stepcount)) {
		bool pusherr = false;
		switch (cpu->excno) {
		case EX_DF: case EX_TS: case EX_NP: case EX_SS: case EX_GP:
		case EX_PF:
			pusherr = true;
		}
		cpu->next_ip = cpu->ip;

		TRY1(call_isr(cpu, cpu->excno, pusherr, 1));
	}
}

void cpu_setax(CPUI386 *cpu, u16 ax)
{
	sreg16(0, ax);
}

u16 cpu_getax(CPUI386 *cpu)
{
	return lreg16(0);
}

void cpu_setexc(CPUI386 *cpu, int excno, uword excerr)
{
	cpu->excno = excno;
	cpu->excerr = excerr;
}

void cpui386_reset(CPUI386 *cpu)
{
	for (int i = 0; i < 8; i++) {
		cpu->gpr[i] = 0;
	}
	cpu->flags = 0x2;
	cpu->cpl = 0;
	cpu->halt = false;

	for (int i = 0; i < 8; i++) {
		cpu->seg[i].sel = 0;
		cpu->seg[i].base = 0;
		cpu->seg[i].limit = 0;
		cpu->seg[i].flags = 0;
	}
	cpu->seg[2].flags = (1 << 22);
	cpu->seg[1].flags = (1 << 22);

	cpu->ip = 0xfff0;
	cpu->next_ip = cpu->ip;
	cpu->seg[SEG_CS].sel = 0xf000;
	cpu->seg[SEG_CS].base = 0xf0000;

	cpu->idt.base = 0;
	cpu->idt.limit = 0x3ff;
	cpu->gdt.base = 0;
	cpu->gdt.limit = 0;

	cpu->cr0 = 0;
	cpu->cr2 = 0;
	cpu->cr3 = 0;
	for (int i = 0; i < 8; i++)
		cpu->dr[i] = 0;

	cpu->cc.mask = 0;
	tlb_clear(cpu);
}

void cpui386_reset_pm(CPUI386 *cpu, uint32_t start_addr)
{
	cpui386_reset(cpu);
	cpu->cr0 = 1;
	cpu->seg[SEG_CS].sel = 0x8;
	cpu->seg[SEG_CS].base = 0;
	cpu->seg[SEG_CS].limit = 0xffffffff;
	cpu->seg[SEG_CS].flags = SEG_D_BIT;
	cpu->next_ip = start_addr;
	cpu->cpl = 0;
	cpu->seg[SEG_SS].sel = 0x10;
	cpu->seg[SEG_SS].base = 0;
	cpu->seg[SEG_SS].limit = 0xffffffff;
	cpu->seg[SEG_SS].flags = SEG_B_BIT;

	cpu->seg[SEG_DS] = cpu->seg[SEG_SS];
	cpu->seg[SEG_ES] = cpu->seg[SEG_SS];
}

CPUI386 *cpui386_new(char *phys_mem, long phys_mem_size)
{
	CPUI386 *cpu = malloc(sizeof(CPUI386));
	cpu->tlb.size = tlb_size;
	cpu->tlb.tab = malloc(sizeof(struct tlb_entry) * tlb_size);

	cpu->phys_mem = phys_mem;
	cpu->phys_mem_size = phys_mem_size;

	cpu->cycle = 0;

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

	cpu->iomem = NULL;
	cpu->iomem_read8 = NULL;
	cpu->iomem_write8 = NULL;
	cpu->iomem_read16 = NULL;
	cpu->iomem_write16 = NULL;
	cpu->iomem_read32 = NULL;
	cpu->iomem_write32 = NULL;

	cpu->fpu = NULL;

	cpui386_reset(cpu);
	return cpu;
}

void activate()
{
	verbose = true;
	freopen("/tmp/xlog", "w", stderr);
	setlinebuf(stderr);
}

static void cpu_debug(CPUI386 *cpu)
{
	static int nest;
	if (nest >= 1)
		return;
	nest++;
	bool code32 = cpu->seg[SEG_CS].flags & SEG_D_BIT;
	bool stack32 = cpu->seg[SEG_SS].flags & SEG_B_BIT;

	fprintf(stderr, "IP %08x|AX %08x|CX %08x|DX %08x|BX %08x|SP %08x|BP %08x|SI %08x|DI %08x|FL %08x|CS %04x|DS %04x|SS %04x|ES %04x|FS %04x|GS %04x|CR0 %08x|CR2 %08x|CR3 %08x|CPL %d|IOPL %d|CSBASE %08x/%08x|DSBASE %08x/%08x|SSBASE %08x/%08x|ESBASE %08x/%08x|GSBASE %08x/%08x %c%c\n",
		cpu->ip, cpu->gpr[0], cpu->gpr[1], cpu->gpr[2], cpu->gpr[3],
		cpu->gpr[4], cpu->gpr[5], cpu->gpr[6], cpu->gpr[7],
		cpu->flags, SEGi(SEG_CS), SEGi(SEG_DS), SEGi(SEG_SS),
		SEGi(SEG_ES), SEGi(SEG_FS), SEGi(SEG_GS),
		cpu->cr0, cpu->cr2, cpu->cr3, cpu->cpl, get_IOPL(cpu),
		cpu->seg[SEG_CS].base, cpu->seg[SEG_CS].limit,
		cpu->seg[SEG_DS].base, cpu->seg[SEG_DS].limit,
		cpu->seg[SEG_SS].base, cpu->seg[SEG_SS].limit,
		cpu->seg[SEG_ES].base, cpu->seg[SEG_ES].limit,
		cpu->seg[SEG_GS].base, cpu->seg[SEG_GS].limit,
		code32 ? 'D' : ' ', stack32 ? 'B' : ' ');
	uword cr2, excno, excerr;
	cr2 = cpu->cr2;
	excno = cpu->excno;
	excerr = cpu->excerr;
	fprintf(stderr, "code: ");
	for (int i = 0; i < 32; i++) {
		OptAddr res;
		if(translate8(cpu, &res, 1, SEG_CS, cpu->ip + i))
			fprintf(stderr, " %02x", load8(cpu, &res));
		else
			fprintf(stderr, " ??");
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "stack: ");
	uword sp_mask = cpu->seg[SEG_SS].flags & SEG_B_BIT ? 0xffffffff : 0xffff;
	for (int i = 0; i < 32; i++) {
		OptAddr res;
		if(translate8(cpu, &res, 1, SEG_SS, (cpu->gpr[4] + i) & sp_mask))
			fprintf(stderr, " %02x", load8(cpu, &res));
		else
			fprintf(stderr, " ??");
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "stkf : ");
	for (int i = 0; i < 32; i++) {
		OptAddr res;
		if(translate8(cpu, &res, 1, SEG_SS, (cpu->gpr[5] + i) & sp_mask))
			fprintf(stderr, " %02x", load8(cpu, &res));
		else
			fprintf(stderr, " ??");
	}
	fprintf(stderr, "\n");

	cpu->cr2 = cr2;
	cpu->excno = excno;
	cpu->excerr = excerr;
	nest--;
}
