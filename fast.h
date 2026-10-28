/*
 * A fast path for tiny386's CPU (built by fast.c, after i386.c).
 *
 * Common instructions run here, on tiny386's own state and with its own instruction macros (lazy flags
 * included); the rest goes to cpu_exec1 one instruction at a time. Handlers hand over before they change
 * anything, so tiny386 redoes the instruction from its start; faults are raised that way too.
 *
 * Instruction bytes are read through a host pointer, memory operands go through a small TLB of our own
 * (linear page -> host address), and each handler dispatches the next instruction itself. With -DFAST_PD,
 * runs of instructions are also decoded once into blocks of uops (fast_pd.h; uses more memory).
 *
 * -DFAST_VERIFY: every instruction is redone by cpu_exec1 and the results compared (slow; for testing).
 */

/* host memory is little-endian, as in i386.c; on MIPS or with -DI386_ALIGNED_ONLY (as i386.c), the compiler takes
 * unaligned 16/32-bit accesses apart */
#if defined(__mips__) || defined(I386_ALIGNED_ONLY)
typedef u16 __attribute__((may_alias, aligned(1))) u16a;
typedef u32 __attribute__((may_alias, aligned(1))) u32a;
#else
typedef u16 __attribute__((may_alias)) u16a;
typedef u32 __attribute__((may_alias)) u32a;
#endif

/* ---- TLB: linear page -> host address of RAM */
#define FTLB_N 1024
struct ftlb_entry {
	uword rtag, wtag;   /* the page mapped for reads / for writes, or -1 */
	uintptr_t delta;    /* host address = linear address + delta */
#if UINTPTR_MAX == 0xffffffff
	uword pad;          /* 16 bytes: index by shift */
#endif
};
/* user pages and supervisor pages differ under paging: one TLB for CPL 3, one for CPL 0-2 */
static struct ftlb_entry ftlb_both[2][FTLB_N];
static struct ftlb_entry *ftlb = ftlb_both[0];
static uword ftlb_cr0 = -1, ftlb_cr3;
static unsigned ftlb_gen;
static CPUI386 *ftlb_cpu;           /* the CPU and RAM it maps for (one TLB for all CPUs) */
static const void *ftlb_mem;
/* without paging, linear = physical in real and protected mode alike */
#define FTLB_CR0 (CR0_PG | CR0_WP)

static inline struct ftlb_entry *ftlb_for(CPUI386 *cpu)
{
	return ftlb_both[(cpu->cr0 & CR0_PG) && cpu->cpl == 3];
}

static void ftlb_flush(CPUI386 *cpu)
{
	for (int k = 0; k < 2; k++)
		for (int i = 0; i < FTLB_N; i++)
			ftlb_both[k][i].rtag = ftlb_both[k][i].wtag = -1;
	ftlb_cr0 = cpu->cr0 & FTLB_CR0;
	ftlb_cr3 = cpu->cr3;
	ftlb_gen = tlb_gen;
	ftlb_cpu = cpu;
	ftlb_mem = cpu->phys_mem;
	ftlb = ftlb_for(cpu);
}

/* flushed with tiny386's TLB (tlb_gen), when paging or CR3 changes, or for another CPU (cpui386_step) */
static inline void ftlb_check(CPUI386 *cpu)
{
	if (unlikely((cpu->cr0 & FTLB_CR0) != ftlb_cr0 || ((cpu->cr0 & CR0_PG) && cpu->cr3 != ftlb_cr3) ||
		     tlb_gen != ftlb_gen))
		ftlb_flush(cpu);
	else
		ftlb = ftlb_for(cpu);
}

/* host address of a size-byte access, filling the TLB; NULL if not plain RAM, across pages, or faulting */
static noinline u8 *ftlb_miss(CPUI386 *cpu, uword lin, int size, int write)
{
	if ((lin & 0xfff) > 0x1000 - size)
		return NULL;
	uword pg = lin >> 12;
	struct ftlb_entry *e = &ftlb[pg & (FTLB_N - 1)];
	uword paddr;
	if (cpu->cr0 & CR0_PG) {
		if (!translate_lpgno(cpu, write ? 2 : 1, pg, lin, cpu->cpl, &paddr))
			return NULL;
		paddr &= ~0xfff;
	} else {
		paddr = pg << 12;
	}
	if (in_iomem(paddr) || paddr >= (uword) cpu->phys_mem_size)
		return NULL;
	uintptr_t delta = (uintptr_t) cpu->phys_mem + paddr - (pg << 12);
	if (e->delta != delta || e->rtag != pg)
		e->wtag = -1;
	e->delta = delta;
	e->rtag = pg;
	if (write)
		e->wtag = pg;
	return (u8 *) (uintptr_t) (lin + delta);
}

/* MMIO (VGA memory): physical address of an access within one page, or -1 */
static noinline uword fast_mmio_addr(CPUI386 *cpu, uword lin, int size, int write)
{
	if ((lin & 0xfff) > 0x1000 - size || !cpu->cb.iomem_read8)
		return -1;
	uword paddr = lin;
	if ((cpu->cr0 & CR0_PG) && !translate_lpgno(cpu, write ? 2 : 1, lin >> 12, lin, cpu->cpl, &paddr))
		return -1;
	return in_iomem(paddr) ? paddr : (uword) -1;
}

static inline u32 fast_io_read(CPUI386 *cpu, uword paddr, int size)
{
	return size == 1 ? cpu->cb.iomem_read8(cpu->cb.iomem, paddr) :
	       size == 2 ? cpu->cb.iomem_read16(cpu->cb.iomem, paddr) : cpu->cb.iomem_read32(cpu->cb.iomem, paddr);
}

static inline void fast_io_write(CPUI386 *cpu, uword paddr, int size, u32 v)
{
	if (size == 1) cpu->cb.iomem_write8(cpu->cb.iomem, paddr, v);
	else if (size == 2) cpu->cb.iomem_write16(cpu->cb.iomem, paddr, v);
	else cpu->cb.iomem_write32(cpu->cb.iomem, paddr, v);
}

/* where an access goes: 1 RAM (*host), 2 MMIO (*paddr), 0 tiny386 */
static noinline int fast_where(CPUI386 *cpu, uword lin, int size, int write, u8 **host, uword *paddr)
{
	struct ftlb_entry *e = &ftlb[(lin >> 12) & (FTLB_N - 1)];
	if ((write ? e->wtag : e->rtag) == lin >> 12 && (lin & 0xfff) <= (uword) (0x1000 - size)) {
		*host = (u8 *) (uintptr_t) (lin + e->delta);
		return 1;
	}
	if ((*host = ftlb_miss(cpu, lin, size, write)))
		return 1;
	*paddr = fast_mmio_addr(cpu, lin, size, write);
	return *paddr != (uword) -1 ? 2 : 0;
}

/* protected-mode null segments (tiny386's segcheck faults on them): their accesses go to tiny386 */
static inline unsigned fast_nullsegs(CPUI386 *cpu)
{
	unsigned m = 0;
	if (cpu->cr0 & 1) {
		for (int i = 0; i < 6; i++)
			if (cpu->seg[i].limit == 0 && (cpu->seg[i].sel & ~0x3) == 0)
				m |= 1 << i;
	}
	return m;
}

/* ---- operands */
static const u8 fast_r8off[8] = { 0, 4, 8, 12, 1, 5, 9, 13 };   /* AL CL DL BL AH CH DH BH in gprx */
#define fr8(i) (((u8 *) cpu->gprx)[fast_r8off[i]])
#define fw8(i, v) (((u8 *) cpu->gprx)[fast_r8off[i]] = (v))
/* memory through host pointers (u16a, u32a) */
#define fm8(p) (*(u8 *) (p))
#define fm16(p) (*(u16a *) (p))
#define fm32(p) (*(u32a *) (p))
#ifndef FAST_VERIFY
#define fs8(p, v) (*(u8 *) (p) = (v))
#define fs16(p, v) (*(u16a *) (p) = (v))
#define fs32(p, v) (*(u32a *) (p) = (v))
#define FMEMCPY memcpy
#define FMEMSET memset
#define FV_BEGIN
#define FV_SKIP
#define FV_END(eip)
#else
#include "fast_verify.h"
#endif

/* CMP and TEST without tiny386's JZ/JNZ lookahead (it uses its fetch state) */
#define FCMPb(...) AOP0_helper(SUB,  8, -, __VA_ARGS__)
#define FCMPw(...) AOP0_helper(SUB, 16, -, __VA_ARGS__)
#define FCMPd(...) AOP0_helper(SUB, 32, -, __VA_ARGS__)
#define FTESTb(...) LOP0_helper(AND,  8, &, __VA_ARGS__)
#define FTESTw(...) LOP0_helper(AND, 16, &, __VA_ARGS__)
#define FTESTd(...) LOP0_helper(AND, 32, &, __VA_ARGS__)

/* offset of a memory operand (mod != 3); sets the default segment unless overridden */
static const u8 fast_ea16_base[8] = { 3, 3, 5, 5, 6, 7, 5, 3 };
static const u8 fast_ea16_index[8] = { 6, 7, 6, 7, 0, 0, 0, 0 };
static inline __attribute__((always_inline)) uword fast_ea(CPUI386 *cpu, const u8 **ppc, u8 modrm, int adsz16, int *seg)
{
	const u8 *pc = *ppc;
	int mod = modrm >> 6, rm = modrm & 7;
	uword a;
	if (adsz16) {
		if (mod == 0 && rm == 6) {
			a = *(u16a *) pc;
			pc += 2;
			if (*seg < 0)
				*seg = SEG_DS;
		} else {
			a = cpu->gprx[fast_ea16_base[rm]].r16 + (cpu->gprx[fast_ea16_index[rm]].r16 & -(uword) (rm < 4));
			if (mod == 1)
				a += (s8) *pc++;
			else if (mod == 2) {
				a += *(u16a *) pc;
				pc += 2;
			}
			a &= 0xffff;
			if (*seg < 0)
				*seg = (rm == 2 || rm == 3 || rm == 6) ? SEG_SS : SEG_DS;
		}
	} else {
		int dseg = SEG_DS;
		if (rm == 4) {
			u8 sib = *pc++;
			int b = sib & 7, i = (sib >> 3) & 7;
			if (b == 5 && mod == 0) {
				a = *(u32a *) pc;
				pc += 4;
			} else {
				a = REGi(b);
				if (b == 4 || b == 5)
					dseg = SEG_SS;
			}
			if (i != 4)
				a += REGi(i) << (sib >> 6);
		} else if (rm == 5 && mod == 0) {
			a = *(u32a *) pc;
			pc += 4;
		} else {
			a = REGi(rm);
			if (rm == 5)
				dseg = SEG_SS;
		}
		if (mod == 1)
			a += (s8) *pc++;
		else if (mod == 2) {
			a += *(u32a *) pc;
			pc += 4;
		}
		if (*seg < 0)
			*seg = dseg;
	}
	*ppc = pc;
	return a;
}

/* get_CF for the common last operations, inline */
static inline __attribute__((always_inline)) int fast_get_CF(CPUI386 *cpu)
{
	if (!(cpu->cc.mask & CF))
		return !!(cpu->flags & CF);
	switch (cpu->cc.op) {
	case CC_ADC: return cpu->cc.dst <= cpu->cc.src2;
	case CC_ADD: return cpu->cc.dst < cpu->cc.src2;
	case CC_SBB: return cpu->cc.src1 <= cpu->cc.src2;
	case CC_SUB: return cpu->cc.src1 < cpu->cc.src2;
	case CC_SHL: case CC_SHR: case CC_SAR: return cpu->cc.dst2 & 1;
	case CC_AND: case CC_OR: case CC_XOR: return 0;
	}
	return (get_CF)(cpu);
}
#define get_CF(cpu) fast_get_CF(cpu)

/* Jcc/SETcc conditions; after CMP or SUB, from the operands directly */
static noinline int fast_cond_slow(CPUI386 *cpu, int c)
{
	int cond;
	switch (c >> 1) {
	case 0: cond = get_OF(cpu); break;
	case 1: cond = get_CF(cpu); break;
	case 2: cond = get_ZF(cpu); break;
	case 3: cond = get_ZF(cpu) || get_CF(cpu); break;
	case 4: cond = get_SF(cpu); break;
	case 5: cond = get_PF(cpu); break;
	case 6: cond = get_SF(cpu) != get_OF(cpu); break;
	default: cond = get_ZF(cpu) || get_SF(cpu) != get_OF(cpu); break;
	}
	return cond ^ (c & 1);
}

static inline __attribute__((always_inline)) int fast_cond(CPUI386 *cpu, int c)
{
	if ((c >> 1) == 2)
		return get_ZF(cpu) ^ (c & 1);
	if (cpu->cc.op == CC_SUB && cpu->cc.mask == (CF | PF | AF | ZF | SF | OF)) {
		/* operands are kept sign-extended: their order holds signed and unsigned */
		uword a = cpu->cc.src1, b = cpu->cc.src2;
		int cond;
		switch (c >> 1) {
		case 1: cond = a < b; break;
		case 3: cond = a <= b; break;
		case 4: cond = (sword) cpu->cc.dst < 0; break;
		case 6: cond = (sword) a < (sword) b; break;
		case 7: cond = (sword) a <= (sword) b; break;
		default: return fast_cond_slow(cpu, c);
		}
		return cond ^ (c & 1);
	}
	return fast_cond_slow(cpu, c);
}

/* ---- code window: the RAM around CS:eip (unpaged: below 640K, or from the BIOS up; paged: the page).
 * It ends 15 bytes early, so any instruction starting in it lies in it. */
struct fast_win { const u8 *pc, *lo; uword len; uintptr_t ipd; };
static noinline bool fast_window(CPUI386 *cpu, uword eip, struct fast_win *w)
{
	uword lin = cpu->seg[SEG_CS].base + eip;
	u8 *host, *start;
	uword size;
	if (cpu->cr0 & CR0_PG) {
		struct ftlb_entry *e = &ftlb[(lin >> 12) & (FTLB_N - 1)];
		if (e->rtag == lin >> 12)
			host = (u8 *) (uintptr_t) (lin + e->delta);
		else if (!(host = ftlb_miss(cpu, lin, 1, 0)))
			return false;
		if ((uword) (host - cpu->phys_mem) >= (uword) cpu->phys_mem_size)
			return false;
		start = host - (lin & 0xfff);
		size = 4096;
	} else {
		uword b0, b1;
		if (lin < 0xa0000) {
			b0 = 0;
			b1 = 0xa0000;
		} else if (lin >= 0xc0000 && lin < (uword) cpu->phys_mem_size) {
			b0 = 0xc0000;
			b1 = cpu->phys_mem_size;
		} else {
			return false;
		}
		start = cpu->phys_mem + b0;
		host = cpu->phys_mem + lin;
		size = b1 - b0;
	}
	if ((uword) (host - start) >= size - 15)
		return false;
	w->pc = host;
	w->lo = start;
	w->len = size - 15;
	w->ipd = (uintptr_t) host - eip;
	return true;
}


#ifdef FAST_PD
#include "fast_pd.h"
#endif

/*
 * Run up to stepcount instructions, as cpu_exec1: false on an exception (cpu->excno, cpu->ip at the instruction).
 * The handlers (fast_ops.h) are compiled three times: for 32-bit and for 16-bit code with the operand and address
 * sizes fixed, and a generic copy that 66/67 prefixes switch to.
 * (reorder-blocks-algorithm=simple: GCC's default moves cold paths out of branch range in this big function.)
 */
/* i386.c's #DE (DIV, IDIV) leaves fast_exec through fault, as the other exceptions */
#pragma push_macro("THROW0")
#undef THROW0
#define THROW0(ex) do { cpu->excno = (ex); goto fault; } while (0)
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3", "reorder-blocks-algorithm=simple")))
#endif
static bool fast_exec(CPUI386 *cpu, int stepcount)
{
#define FL_CAT2(a, b) a##b
#define FL_CAT(a, b) FL_CAT2(a, b)
#define FL(x) FL_CAT(x, FAST_SFX)   /* a label of the copy being compiled */
#define FAST_SFX _g
#include "fast_tab.h"
#undef FAST_SFX
#define FAST_SFX _32
#include "fast_tab.h"
#undef FAST_SFX
#define FAST_SFX _16
#include "fast_tab.h"
#undef FAST_SFX
#ifdef FAST_PD
#define PD_LABEL(n) [PD_##n] = &&pd_##n,
	static const void *const pd_tab[PD_N] = { PD_LIST(PD_LABEL) };
#undef PD_LABEL
#endif

	/* virtual-8086 mode runs as real mode, but traps (INT, IRET, I/O, IF with IOPL < 3) go to tiny386 */
	const uword vm0 = cpu->flags & VM;

	int steps = stepcount - 1;    /* instructions left after this one */
	int nslow = 0;                /* instructions done by tiny386 (it counts them) */
	const u8 *pc;                 /* next instruction byte (host address) */
	const u8 *ins;                /* current instruction */
	const u8 *win_lo, *win_end;   /* code window: instructions start in [win_lo, win_end) */
	uintptr_t ipd;                /* eip = pc - ipd */
	bool code16;
	const void *const *ops_cur;   /* ops_32 or ops_16 */
	uword sp_mask;
	unsigned nullsegs;
	/* prefixes: bit 0 16-bit operands, bit 1 16-bit addresses, bits 2-3 REP (1) / REPNE (2),
	 * bits 4-6 segment override + 1; pfx0: none */
	unsigned pfx, pfx0;
	/* the generic copy's; the fixed-size copies define their own */
#define opsz16 (pfx & 1)
#define adsz16 ((pfx >> 1) & 1)
#define FAST_CODE16 code16
#define PFX0 pfx0
#define FAST_DTAB ops_cur
#define rep ((pfx >> 2) & 3)
#define SEG_OVERRIDE ((int) (pfx >> 4) - 1)
	int seg = -1;                 /* memory operand's segment */
	int strn;                     /* string instructions: element size */
	uword eip;
	uword mlin;                   /* MMIO access: linear address, size, value (stores), register (loads) */
	u32 mval;
	int msize, mreg;
#ifdef FAST_PD
	/* pre-decoded blocks (fast_pd.h): the uop running, its block, the block's code, the jump's link slot */
	const struct pd_uop *pu = NULL;
	struct pd_block *bk, **lk;
	const u8 *bh = NULL;
	bool pd_call = false;         /* in pd_classic: one instruction by the handlers below, pd_saved steps left */
	int pd_saved = 0;
	pd_h = pd_tab;
	/* a block checks the steps left at its end: up to PD_MAX - 1 instructions more than asked (cpu->cycle counts
	 * them), so blocks only for more steps than that; fewer (single steps) are exact. (Stopping exactly costs 13%
	 * on an ESP32-P4: slices then end inside blocks, and the next one starts new blocks there.) */
	const bool pd_on = stepcount > PD_MAX && pd_init(cpu);
	pd_ep++;                      /* devices may have written code since */
#define PD_UNCALL do { if (pd_call) { pd_call = false; steps += pd_saved; } } while (0)
#define PD_GO_ON (!cpu->halt && (cpu->flags & VM) == vm0 && !(cpu->intr && (cpu->flags & IF)))
#define PD_ENTER do { if (pd_on) goto pd_enter; } while (0)
#define PD_JUMPED do { if (pd_on) goto pd_jumped; } while (0)
#else
#define PD_ENTER do { } while (0)
#define PD_JUMPED do { } while (0)
#define PD_UNCALL do { } while (0)
#endif

#define EIP_OF(p) ((uword) ((uintptr_t) (p) - ipd))
	/* each handler dispatches the next instruction itself */
#define DISPATCH do { ins = pc; pfx = PFX0; FV_BEGIN; goto *FAST_DTAB[*pc++]; } while (0)
#define NEXT do { \
		FV_END(EIP_OF(pc)); \
		if (unlikely(--steps < 0)) goto out; \
		if (unlikely((uintptr_t) pc >= (uintptr_t) win_end)) goto refill; \
		DISPATCH; \
	} while (0)
	/* jumps; 16-bit code wraps at 64K. NEXT only checks the window's end, so a jump below its start moves
	 * the end there. */
#define JUMP_BELOW do { if (unlikely((uintptr_t) pc < (uintptr_t) win_lo)) win_end = pc; } while (0)
#define JUMP_REL(d) do { \
		if (FAST_CODE16) pc = (const u8 *) (ipd + ((EIP_OF(pc) + (d)) & 0xffff)); \
		else pc += (d); \
		PD_JUMPED; \
		JUMP_BELOW; \
	} while (0)
#define JUMP_ABS(neweip) do { pc = (const u8 *) (ipd + (uword) (neweip)); PD_JUMPED; JUMP_BELOW; } while (0)
	/* host address of a memory operand, or the instruction goes to tiny386. The tag is compared with the
	 * page of the last byte, so an access across pages misses (and ftlb_miss refuses it). */
#define FPTR(p, sg, off, size, wr) do { \
		if (unlikely(nullsegs) && (nullsegs & (1 << (sg)))) goto slow; \
		uword _lin = cpu->seg[sg].base + (off); \
		uword _pg = _lin >> 12; \
		struct ftlb_entry *_e = &ftlb[_pg & (FTLB_N - 1)]; \
		if (likely(((wr) ? _e->wtag : _e->rtag) == ((_lin + (size) - 1) >> 12))) \
			p = (u8 *) (uintptr_t) (_lin + _e->delta); \
		else if (!(p = ftlb_miss(cpu, _lin, (size), (wr)))) \
			goto slow; \
	} while (0)
	/* as FPTR, but an access that isn't to RAM goes to LABEL (mlin, msize set) to try MMIO */
#define FPTR_IO(p, sg, off, size, wr, LABEL) do { \
		if (unlikely(nullsegs) && (nullsegs & (1 << (sg)))) goto slow; \
		uword _lin = cpu->seg[sg].base + (off); \
		uword _pg = _lin >> 12; \
		struct ftlb_entry *_e = &ftlb[_pg & (FTLB_N - 1)]; \
		if (likely(((wr) ? _e->wtag : _e->rtag) == ((_lin + (size) - 1) >> 12))) \
			p = (u8 *) (uintptr_t) (_lin + _e->delta); \
		else if (!(p = ftlb_miss(cpu, _lin, (size), (wr)))) { \
			mlin = _lin; \
			msize = (size); \
			goto LABEL; \
		} \
	} while (0)
#define EA_OFF(off, m) \
	seg = SEG_OVERRIDE; \
	uword off = fast_ea(cpu, &pc, m, adsz16, &seg);
#define EA_PTR(p, m, size, wr) \
	seg = SEG_OVERRIDE; \
	uword _off = fast_ea(cpu, &pc, m, adsz16, &seg); \
	FPTR(p, seg, _off, size, wr)
	/* stack slot at SP + d */
#define STACK_PTR(p, d, size, wr) do { \
		uword _sp = (REGi(4) + (d)) & sp_mask; \
		if ((size) > 4 && _sp > sp_mask - ((size) - 1)) goto slow;   /* wraps around: tiny386 */ \
		FPTR(p, SEG_SS, _sp, size, wr); \
	} while (0)
#define SP_ADD(d) set_sp(REGi(4) + (d), sp_mask)
#define PMODE (cpu->cr0 & 1)                                   /* protected or virtual-8086 mode */
#define PROTECTED (PMODE && !(cpu->flags & VM))                /* protected mode */
#define V86_IOPL3 (!(cpu->flags & VM) || get_IOPL(cpu) == 3)   /* not trapped in virtual-8086 mode */
	/* protected-mode load of DS ES FS GS; false: the instruction goes to tiny386 */
#define FAST_LOAD_SEG(sg, sel) (set_seg(cpu, (sg), (sel)) ? (nullsegs = fast_nullsegs(cpu), true) : false)
	/* instructions done here, for cpui386_get_cycle */
#define FAST_COUNT() do { PD_UNCALL; int _n = stepcount - 1 - steps - nslow; if (_n > 0) cpu->cycle += _n; } while (0)
	/* after CS changed (eip: the next instruction) */
#define RELOAD do { \
		FV_END(eip); \
		if (--steps < 0) { cpu->next_ip = eip; goto out_ip; } \
		goto reload; \
	} while (0)
	/* protected-mode far CALL/JMP/RETF/IRET by pmcall/pmret; a fault is raised at the instruction, as tiny386 does */
#define PM_FAR(call) do { \
		cpu->ip = EIP_OF(ins); \
		cpu->next_ip = EIP_OF(pc); \
		if (!(call)) goto fault; \
		ftlb_check(cpu); \
		eip = cpu->next_ip; \
		if ((cpu->flags & VM) != vm0 || (cpu->intr && (cpu->flags & IF))) { FV_END(eip); goto out_ip; } \
		RELOAD; \
	} while (0)
	/* code window around eip, or the instruction goes to tiny386 */
#define WINDOW(eip) do { \
		struct fast_win _w; \
		if (!fast_window(cpu, (eip), &_w)) goto slow_eip; \
		pc = _w.pc; win_lo = _w.lo; win_end = _w.lo + _w.len; ipd = _w.ipd; \
	} while (0)

	eip = cpu->next_ip;
	cpu->ifetch.paddr = 0;
	ftlb_check(cpu);
reload:   /* after mode, CS or segments changed outside the handlers; eip: the next instruction */
	code16 = cpu->code16;
	pfx0 = code16 ? 3 : 0;
	ops_cur = code16 ? ops_16 : ops_32;
	sp_mask = cpu->sp_mask;
	nullsegs = fast_nullsegs(cpu);
	WINDOW(eip);
	PD_ENTER;
	DISPATCH;
refill:   /* the next instruction is outside the window */
	eip = EIP_OF(pc);
	WINDOW(eip);
	PD_ENTER;
	DISPATCH;

#define FAST_SFX _g
#include "fast_ops.h"
#undef FAST_SFX
#undef opsz16
#undef adsz16
#undef FAST_CODE16
#undef PFX0
#undef FAST_DTAB
#define opsz16 0
#define adsz16 0
#define FAST_CODE16 0
#define PFX0 0u
#define FAST_DTAB ops_32
#define FAST_SFX _32
#include "fast_ops.h"
#undef FAST_SFX
#undef opsz16
#undef adsz16
#undef FAST_CODE16
#undef PFX0
#undef FAST_DTAB
#define opsz16 1
#define adsz16 1
#define FAST_CODE16 1
#define PFX0 3u
#define FAST_DTAB ops_16
#define FAST_SFX _16
#include "fast_ops.h"
#undef FAST_SFX
#undef opsz16
#undef adsz16
#undef FAST_CODE16
#undef PFX0
#undef FAST_DTAB
#define opsz16 (pfx & 1)
#define adsz16 ((pfx >> 1) & 1)
#define FAST_CODE16 code16
#define PFX0 pfx0
#define FAST_DTAB ops_cur

#ifdef FAST_PD
#include "fast_pd_ops.h"
#endif

	/* MMIO for the MOVs (mlin, msize; mval to store, mreg to load into) */
mmio_st: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 1);
	if (pa == (uword) -1) goto slow;
	FV_SKIP;
	fast_io_write(cpu, pa, msize, mval);
	NEXT; }
mmio_ld: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 0);
	if (pa == (uword) -1) goto slow;
	FV_SKIP;
	u32 v = fast_io_read(cpu, pa, msize);
	if (msize == 1) fw8(mreg, v); else if (msize == 2) sreg16(mreg, v); else sreg32(mreg, v);
	NEXT; }

	/* ---- leaving */
out:	/* steps done; pc: the next instruction */
#ifdef FAST_PD
	if (pd_call) {   /* pd_classic's instruction done: on in its block if it went to the next one */
		PD_UNCALL;
		if (PD_GO_ON) {
			if (pc == bh + pu[1].ip) {
				pu++;
				goto *pu->h;
			}
			goto pd_go;
		}
	}
#endif
	cpu->next_ip = EIP_OF(pc);
out_ip:
#ifdef FAST_PD
	if (pd_call) {   /* pd_classic's instruction changed CS or the like */
		PD_UNCALL;
		if (steps >= 0 && PD_GO_ON) {
			eip = cpu->next_ip;
			goto reload;
		}
	}
#endif
	FAST_COUNT();
	return true;

fault:	/* an exception at the current instruction (cpu->excno): counted with it, as cpu_exec1 counts */
	FV_SKIP;
	FAST_COUNT();
	cpu->cycle++;
	return false;

slow:	/* the current instruction goes to tiny386 */
	eip = EIP_OF(ins);
slow_eip:
	cpu->next_ip = eip;
	cpu->ifetch.paddr = 0;
	{
		bool ok = cpu_exec1(cpu, 1);
		cpu->ifetch.paddr = 0;
		if (!ok) {
			FAST_COUNT();
			return false;
		}
		ftlb_check(cpu);
	}
	/* cpu_exec1 counted it: into nslow only with its step, or FAST_COUNT leaves it out twice when stopping here */
	if (cpu->halt || (cpu->flags & VM) != vm0 || (cpu->intr && (cpu->flags & IF)) || (nslow++, --steps < 0)) {
#ifdef FAST_PD
		if (pd_call) {   /* pd_classic's instruction, by tiny386 */
			PD_UNCALL;
			if (steps >= 0 && PD_GO_ON) {
				eip = cpu->next_ip;
				goto reload;
			}
		}
#endif
		FAST_COUNT();
		return true;
	}
	eip = cpu->next_ip;
	goto reload;
#undef opsz16
#undef adsz16
#undef rep
#undef FAST_CODE16
#undef PFX0
#undef FAST_DTAB
#undef FL
#undef PD_ENTER
#undef PD_JUMPED
#undef PD_UNCALL
#undef PD_GO_ON
}
#pragma pop_macro("THROW0")

void cpui386_reset(CPUI386 *cpu)
{
	ftlb_cr0 = -1;
	tiny386_reset(cpu);
}

/* tiny386's cpui386_step, with fast_exec for cpu_exec1 */
void cpui386_step(CPUI386 *cpu, int stepcount)
{
	if ((cpu->flags & IF) && cpu->intr) {
		cpu->intr = false;
		cpu->halt = false;
		int no = cpu->cb.pic_read_irq(cpu->cb.pic);
		cpu->ip = cpu->next_ip;
		TRY1(call_isr(cpu, no, false, 1));
	}

	if (cpu->halt) {
		usleep(1);
		return;
	}

	if (cpu != ftlb_cpu || cpu->phys_mem != ftlb_mem)
		ftlb_cr0 = -1;   /* another CPU or RAM: flush */
	int ret = fast_exec(cpu, stepcount);
	cpu->ifetch.paddr = 0;
	if (!ret) {
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
