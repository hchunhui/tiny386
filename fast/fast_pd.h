/*
 * Pre-decoding (FAST_PD) for the fast path in fast.h.
 *
 * Runs of instructions, up to a backward or unconditional jump, are decoded once into blocks of uops
 * (a handler and its operands; a memory operand as base, index, scale, displacement), which fast_exec runs
 * one after another (fast_pd_ops.h). Blocks link to the block they jumped to last.
 *
 * An instruction the decoder doesn't know runs in fast_ops.h's handler (pd_classic); the block goes on after
 * it, or ends there if it may write memory.
 *
 * A block keeps a copy of its code and compares it before it runs if something may have written it:
 * a uop's store to a 128-byte line with blocks' code marks the blocks it overlaps (they decode the written
 * instructions again: self-modifying code), and anything else (fast_ops.h handlers, tiny386, devices)
 * advances pd_ep, which has all blocks compared once.
 */

#ifndef FAST_PD_SIZE
#define FAST_PD_SIZE (2 << 20)   /* memory for blocks; when full, all go */
#endif
#define PD_HASH 8192
#define PD_MAX 48                /* uops in a block, the end included */
#define PD_MAXB 256              /* code bytes in a block at most (pd_wrote looks this far back) */

/* A uop. Memory operand: (*b + (*x << scl) + d) & (0xffffffff >> ams) in segment sg, b and x pointing at
 * registers or pd_zero. r, rm: registers. i: immediate, jump displacement or shift count.
 * link: the block a jump or the block's end went to last. */
struct pd_block;
struct pd_uop {
	const void *h;
	const u32 *b, *x;
	u32 d, i;
	struct pd_block *link;
	u16 ip;                    /* offset of the instruction in the block's code (end: the code's length) */
	u8 r, rm, scl, sg, ams, pad;
};

struct pd_block {
	const u8 *host;            /* the code (host address in guest RAM) */
	struct pd_block *hnext;    /* hash chain */
	u16 n;                     /* uops, the end included */
	u16 nbytes;                /* code bytes (copied after the uops) */
	u16 span;                  /* offset of the last instruction: the code window must reach it */
	u16 cap;                   /* room for uops and code (pd_redo) */
	u8 code16;
	u8 pad[3];
	struct pd_block *lnext;    /* next block starting in the same 128-byte line */
	u32 ep;                    /* pd_ep when the code was last found unchanged */
	u16 dlo, dhi;              /* code bytes [dlo, dhi) stored to by uops since, when pd_ep was dep */
	u32 dep;
	struct pd_uop u[];
};
#define PD_CODE(bk) ((const u8 *) ((bk)->u + (bk)->n))

static const u32 pd_zero;
static u8 *pd_arena, *pd_free;
static struct pd_block **pd_hash;
static unsigned pd_gen;            /* +1 when all blocks go (link slots in them must not be written then) */
static u32 pd_ep;                  /* advanced when anything but a uop may have written code */
static u32 *pd_codeln;             /* per RAM page: a bit per 128-byte line with blocks' code */
static struct pd_block **pd_lnblk; /* per 128-byte line of RAM: blocks starting there */
static uword pd_ram;
static const void *const *pd_h;    /* handler addresses (fast_exec's pd_tab) */
static struct pd_block *pd_cur;    /* the block running (a global: no register for it in the uops) */

/* Handlers, in families indexed by the decoder: sizes b w d; forms r register, m memory, i immediate,
 * c CL (ALU and MOV: rr rm <- r, rm G,E, mr E,G, ri E,I, mi E,I). */
#define PD_S3(X, n) X(n##b) X(n##w) X(n##d)
#define PD_F5(X, n) PD_S3(X, n##_rr) PD_S3(X, n##_rm) PD_S3(X, n##_mr) PD_S3(X, n##_ri) PD_S3(X, n##_mi)
#define PD_SH(X, n) PD_S3(X, n##_ri) PD_S3(X, n##_rc) PD_S3(X, n##_mi) PD_S3(X, n##_mc)
#define PD_J16(X, p) X(p##0) X(p##1) X(p##2) X(p##3) X(p##4) X(p##5) X(p##6) X(p##7) \
	X(p##8) X(p##9) X(p##a) X(p##b) X(p##c) X(p##d) X(p##e) X(p##f)
#define PD_LIST(X) \
	X(end) X(leave) X(classic) X(nop) \
	PD_F5(X, mov) \
	PD_F5(X, add) PD_F5(X, or) PD_F5(X, adc) PD_F5(X, sbb) PD_F5(X, and) PD_F5(X, sub) PD_F5(X, xor) \
	PD_F5(X, cmp) PD_F5(X, test) \
	PD_S3(X, inc_r) PD_S3(X, inc_m) PD_S3(X, dec_r) PD_S3(X, dec_m) \
	X(push_rw) X(push_rd) X(pop_rw) X(pop_rd) X(push_iw) X(push_id) X(push_mw) X(push_md) \
	X(leaw) X(lead) \
	X(zbw_r) X(zbw_m) X(zbd_r) X(zbd_m) X(zwd_r) X(zwd_m) \
	X(sbw_r) X(sbw_m) X(sbd_r) X(sbd_m) X(swd_r) X(swd_m) \
	PD_SH(X, shl) PD_SH(X, shr) PD_SH(X, sar) PD_SH(X, rol) PD_SH(X, ror) PD_SH(X, rcl) PD_SH(X, rcr) \
	PD_S3(X, not_r) PD_S3(X, not_m) PD_S3(X, neg_r) PD_S3(X, neg_m) PD_S3(X, mul_r) PD_S3(X, mul_m) \
	PD_S3(X, imul_r) PD_S3(X, imul_m) PD_S3(X, div_r) PD_S3(X, div_m) PD_S3(X, idiv_r) PD_S3(X, idiv_m) \
	PD_S3(X, xchg_rr) PD_S3(X, xchg_mr) X(setcc_r) X(setcc_m) \
	X(clc) X(stc) X(cmc) X(cld) X(std) X(leavew) X(leaved) \
	X(loop16) X(loop32) X(loope16) X(loope32) X(loopne16) X(loopne32) X(jcxz16) X(jcxz32) \
	PD_S3(X, lods16) PD_S3(X, lods32) PD_S3(X, stos16) PD_S3(X, stos32) PD_S3(X, movs16) PD_S3(X, movs32) \
	PD_S3(X, in_i) PD_S3(X, in_dx) PD_S3(X, out_i) PD_S3(X, out_dx) \
	X(push_sw) X(push_sd) X(pop_sw) X(pop_sd) X(mov_sr) X(mov_sm) X(mov_rs) X(mov_ms) \
	X(lesw) X(lesd) X(enterw) X(enterd) X(pushaw) X(pushad) X(popaw) X(popad) X(pop_mw) X(pop_md) \
	X(cli) X(pushfw) X(pushfd) \
	X(imul2_rw) X(imul2_rd) X(imul2_mw) X(imul2_md) X(imul3_rw) X(imul3_rd) X(imul3_mw) X(imul3_md) \
	X(shld_rw) X(shld_rd) X(shld_mw) X(shld_md) X(shrd_rw) X(shrd_rd) X(shrd_mw) X(shrd_md) \
	X(cbw) X(cwde) X(cwd) X(cdq) \
	PD_J16(X, j16_) PD_J16(X, j32_) X(jmp16) X(jmp32) X(call16) X(call32) \
	X(ret16) X(ret32) X(reti16) X(reti32) \
	X(jmpi_rw) X(jmpi_rd) X(jmpi_mw) X(jmpi_md) X(calli_rw) X(calli_rd) X(calli_mw) X(calli_md)
#define PD_ENUM(n) PD_##n,
enum { PD_LIST(PD_ENUM) PD_N };
#undef PD_ENUM

static void pd_flush(void)
{
	memset(pd_hash, 0, sizeof(*pd_hash) * PD_HASH);
	memset(pd_codeln, 0, (pd_ram >> 12) * sizeof(*pd_codeln));
	memset(pd_lnblk, 0, (pd_ram >> 7) * sizeof(*pd_lnblk));
	pd_free = pd_arena;
	pd_gen++;
}

void *bigmalloc(size_t size);   /* pc.h */
static void *pd_alloc(size_t n)
{
	void *p = bigmalloc(n);
	return p == (void *) -1 ? NULL : p;   /* (mmap's failure) */
}

/* blocks are for one CPU and its RAM at a time: another empties them (the tables are sized by the first RAM;
 * a larger one runs without blocks) */
static bool pd_init(CPUI386 *cpu)
{
	static bool failed;
	static CPUI386 *owner;
	static const void *mem;
	static uword cap;
	const uword ram = cpu->phys_mem_size & ~0xfff;
	if (!pd_arena) {
		if (failed) return false;
		cap = ram;
		pd_hash = pd_alloc(sizeof(*pd_hash) * PD_HASH);
		pd_codeln = pd_alloc((cap >> 12) * sizeof(*pd_codeln));
		pd_lnblk = pd_alloc((cap >> 7) * sizeof(*pd_lnblk));
		pd_arena = pd_alloc(FAST_PD_SIZE);
		if (!pd_hash || !pd_codeln || !pd_lnblk || !pd_arena) {
			failed = true;
			pd_arena = NULL;
			return false;
		}
	} else if (cpu == owner && cpu->phys_mem == mem) {
		return true;
	}
	if (ram > cap)
		return false;
	owner = cpu;
	mem = cpu->phys_mem;
	pd_ram = ram;
	pd_flush();
	return true;
}


static inline unsigned pd_hash_of(const u8 *host) { return ((uintptr_t) host ^ ((uintptr_t) host >> 13)) & (PD_HASH - 1); }

/* is the block's code unchanged? */
static inline bool pd_same(const struct pd_block *bk)
{
	const u8 *h = bk->host, *c = PD_CODE(bk);
	int n = bk->nbytes, k;
	if (n < 4) {
		for (k = 0; k < n; k++)
			if (h[k] != c[k]) return false;
		return true;
	}
	for (k = 0; k < n - 4; k += 4)
		if (*(u32a *) (h + k) != *(u32a *) (c + k)) return false;
	return *(u32a *) (h + n - 4) == *(u32a *) (c + n - 4);
}

/* ---- decoder */

/* a memory operand (mod != 3) into u; returns p past it */
static const u8 *pd_ea(CPUI386 *cpu, const u8 *p, u8 m, bool a16, int sgo, struct pd_uop *u)
{
	int mod = m >> 6, rm = m & 7, sg = SEG_DS;
	u->b = u->x = &pd_zero;
	u->scl = 0;
	u->d = 0;
	if (a16) {
		u->ams = 16;
		if (mod == 0 && rm == 6) {
			u->d = *(u16a *) p;
			p += 2;
		} else {
			u->b = &cpu->gprx[fast_ea16_base[rm]].r32;
			if (rm < 4) u->x = &cpu->gprx[fast_ea16_index[rm]].r32;
			if (mod == 1) u->d = (s8) *p++;
			else if (mod == 2) { u->d = *(u16a *) p; p += 2; }
			if (rm == 2 || rm == 3 || rm == 6) sg = SEG_SS;
		}
	} else {
		u->ams = 0;
		if (rm == 4) {
			u8 sib = *p++;
			int b = sib & 7, i = (sib >> 3) & 7;
			if (b == 5 && mod == 0) {
				u->d = *(u32a *) p;
				p += 4;
			} else {
				u->b = &cpu->gprx[b].r32;
				if (b == 4 || b == 5) sg = SEG_SS;
			}
			if (i != 4) {
				u->x = &cpu->gprx[i].r32;
				u->scl = sib >> 6;
			}
		} else if (rm == 5 && mod == 0) {
			u->d = *(u32a *) p;
			p += 4;
		} else {
			u->b = &cpu->gprx[rm].r32;
			if (rm == 5) sg = SEG_SS;
		}
		if (mod == 1) u->d += (s8) *p++;
		else if (mod == 2) { u->d += *(u32a *) p; p += 4; }
	}
	u->sg = sgo >= 0 ? sgo : sg;
	return p;
}

/* One instruction at p into u (*hi: handler index); returns its end, or NULL if unknown.
 * *stop: the block ends after it. */
static const u8 *pd_one(CPUI386 *cpu, const u8 *p, bool code16, struct pd_uop *u, int *hi, bool *stop)
{
	bool o16 = code16, a16 = code16;
	int sgo = -1, npfx = 0;
	for (;; p++, npfx++) {
		if (npfx > 3) return NULL;
		switch (*p) {
		case 0x66: o16 = !code16; continue;
		case 0x67: a16 = !code16; continue;
		case 0x26: sgo = SEG_ES; continue;
		case 0x2e: sgo = SEG_CS; continue;
		case 0x36: sgo = SEG_SS; continue;
		case 0x3e: sgo = SEG_DS; continue;
		case 0x64: sgo = SEG_FS; continue;
		case 0x65: sgo = SEG_GS; continue;
		}
		break;
	}
	const int sv = o16 ? 1 : 2;   // operand size index: b w d
	u8 op = *p++;
	u8 m;
	*stop = false;
	u->link = NULL;
#define MODRM() (m = *p++, u->r = (m >> 3) & 7, u->rm = m & 7)
#define EA() (p = pd_ea(cpu, p, m, a16, sgo, u))
#define IMM(sz) ((sz) == 0 ? (u32) *p++ : (sz) == 1 ? (p += 2, (u32) *(u16a *) (p - 2)) : (p += 4, *(u32a *) (p - 4)))
	if (op < 0x40 && (op & 7) < 6) {   // ALU: ADD OR ADC SBB AND SUB XOR CMP
		const int base = PD_add_rrb + (op >> 3) * 15, f = op & 7, sz = f & 1 ? sv : 0;
		if (f < 4) {
			MODRM();
			if (m >= 0xc0) {
				if (f >= 2) { u8 t = u->r; u->r = u->rm; u->rm = t; }   // rr: rm op= r
				*hi = base + sz;
			} else {
				EA();
				*hi = base + (f < 2 ? 6 : 3) + sz;
			}
		} else {
			u->rm = 0;
			u->i = IMM(sz);
			*hi = base + 9 + sz;
		}
		return p;
	}
	switch (op) {
	case 0x0f:
		op = *p++;
		if (op >= 0x80 && op <= 0x8f) {   // Jcc rel16/32
			if (o16 != code16) return NULL;
			u->i = o16 ? (u32) (s32) (s16) *(u16a *) p : *(u32a *) p;
			p += o16 ? 2 : 4;
			*hi = (code16 ? PD_j16_0 : PD_j32_0) + (op & 15);
			*stop = (s32) u->i < 0;   // backward: a loop, the block ends
			return p;
		}
		switch (op) {
		case 0xa0: case 0xa8: u->r = op == 0xa0 ? SEG_FS : SEG_GS; *hi = o16 ? PD_push_sw : PD_push_sd; return p;
		case 0xa1: case 0xa9: u->r = op == 0xa1 ? SEG_FS : SEG_GS; *hi = o16 ? PD_pop_sw : PD_pop_sd; return p;
		case 0x90 ... 0x9f:   // SETcc
			MODRM();
			u->i = op & 15;
			if (m >= 0xc0) *hi = PD_setcc_r;
			else { EA(); *hi = PD_setcc_m; }
			return p;
		case 0xaf:   // IMUL Gv,Ev
			MODRM();
			if (o16) *hi = m >= 0xc0 ? PD_imul2_rw : (EA(), PD_imul2_mw);
			else *hi = m >= 0xc0 ? PD_imul2_rd : (EA(), PD_imul2_md);
			return p;
		case 0xb6: case 0xb7: case 0xbe: case 0xbf: {   // MOVZX, MOVSX
			if (op & 1 && o16) return NULL;   // Gw,Ew
			MODRM();
			bool mem = m < 0xc0;
			if (mem) EA();
			static const u8 k[2][2][2] = { { { PD_zbw_r, PD_zbd_r }, { 0, PD_zwd_r } },
						       { { PD_sbw_r, PD_sbd_r }, { 0, PD_swd_r } } };
			*hi = k[op >= 0xbe][op & 1][!o16] + mem;
			return p;
		}
		case 0xa4: case 0xac:   // SHLD, SHRD Ev,Gv,Ib
			MODRM();
			if (m < 0xc0) EA();
			u->i = *p++;
			*hi = (op == 0xa4 ? PD_shld_rw : PD_shrd_rw) + !o16 + (m < 0xc0) * 2;
			return p;
		}
		return NULL;
	case 0x40 ... 0x47: u->rm = op & 7; *hi = PD_inc_rb + sv; return p;
	case 0x48 ... 0x4f: u->rm = op & 7; *hi = PD_dec_rb + sv; return p;
	case 0x50 ... 0x57: u->r = op & 7; *hi = o16 ? PD_push_rw : PD_push_rd; return p;
	case 0x58 ... 0x5f: u->r = op & 7; *hi = o16 ? PD_pop_rw : PD_pop_rd; return p;
	case 0x68: u->i = IMM(sv); *hi = o16 ? PD_push_iw : PD_push_id; return p;
	case 0x6a: u->i = (u32) (s32) (s8) *p++; *hi = o16 ? PD_push_iw : PD_push_id; return p;
	case 0x69: case 0x6b:   // IMUL Gv,Ev,I
		MODRM();
		if (m < 0xc0) EA();
		u->i = op == 0x6b ? (u32) (s32) (s8) *p++ : o16 ? (u32) (s32) (s16) *(u16a *) p : *(u32a *) p;
		if (op == 0x69) p += o16 ? 2 : 4;
		*hi = (o16 ? PD_imul3_rw : PD_imul3_rd) + (m < 0xc0) * 2;
		return p;
	case 0x70 ... 0x7f:
		u->i = (u32) (s32) (s8) *p++;
		*hi = (code16 ? PD_j16_0 : PD_j32_0) + (op & 15);
		*stop = (s32) u->i < 0;
		return p;
	case 0x80: case 0x81: case 0x82: case 0x83: {   // ALU E,I
		const int sz = op & 1 ? sv : 0;
		MODRM();
		const int base = PD_add_rrb + u->r * 15;
		if (m >= 0xc0) *hi = base + 9 + sz;
		else { EA(); *hi = base + 12 + sz; }
		u->i = op == 0x83 ? (u32) (s32) (s8) *p++ : IMM(sz);
		return p;
	}
	case 0x84: case 0x85:   // TEST E,G
		MODRM();
		if (m >= 0xc0) *hi = PD_test_rrb + (op & 1 ? sv : 0);
		else { EA(); *hi = PD_test_mrb + (op & 1 ? sv : 0); }
		return p;
	case 0x88 ... 0x8b: {   // MOV
		const int sz = op & 1 ? sv : 0;
		MODRM();
		if (m >= 0xc0) {
			if (op & 2) { u8 t = u->r; u->r = u->rm; u->rm = t; }
			*hi = PD_mov_rrb + sz;
		} else {
			EA();
			*hi = (op & 2 ? PD_mov_rmb : PD_mov_mrb) + sz;
		}
		return p;
	}
	case 0x8d:   // LEA
		MODRM();
		if (m >= 0xc0) return NULL;
		EA();
		*hi = o16 ? PD_leaw : PD_lead;
		return p;
	case 0x90: *hi = PD_nop; return p;
	case 0x98: *hi = o16 ? PD_cbw : PD_cwde; return p;
	case 0x99: *hi = o16 ? PD_cwd : PD_cdq; return p;
	case 0xa0 ... 0xa3: {   // MOV with a direct offset
		const int sz = op & 1 ? sv : 0;
		u->b = u->x = &pd_zero;
		u->scl = 0;
		u->ams = a16 ? 16 : 0;
		u->d = IMM(a16 ? 1 : 2);
		u->sg = sgo >= 0 ? sgo : SEG_DS;
		u->r = 0;
		*hi = (op & 2 ? PD_mov_mrb : PD_mov_rmb) + sz;
		return p;
	}
	case 0xa4: case 0xa5: case 0xaa: case 0xab: case 0xac: case 0xad: {   // MOVS STOS LODS without REP
		const int sz = op & 1 ? sv : 0;
		u->sg = sgo >= 0 ? sgo : SEG_DS;
		*hi = (op >= 0xac ? PD_lods16b : op >= 0xaa ? PD_stos16b : PD_movs16b) + (a16 ? 0 : 3) + sz;
		return p;
	}
	case 0xe4 ... 0xe7: case 0xec ... 0xef: {   // IN, OUT
		const int sz = op & 1 ? sv : 0;
		if (op < 0xe8) u->i = *p++;
		*hi = (op & 2 ? PD_out_ib : PD_in_ib) + (op >= 0xec ? 3 : 0) + sz;
		return p;
	}
	case 0x06: case 0x0e: case 0x16: case 0x1e:   // PUSH Sreg
		u->r = op >> 3;
		*hi = o16 ? PD_push_sw : PD_push_sd;
		return p;
	case 0x07: case 0x1f:   // POP ES, DS
		u->r = op >> 3;
		*hi = o16 ? PD_pop_sw : PD_pop_sd;
		return p;
	case 0x8e:   // MOV Sreg,Ew (not CS, SS)
		MODRM();
		if (u->r == SEG_CS || u->r == SEG_SS || u->r > 5) return NULL;
		if (m >= 0xc0) *hi = PD_mov_sr;
		else { EA(); *hi = PD_mov_sm; }
		return p;
	case 0x8c:   // MOV Ew,Sreg
		MODRM();
		if (u->r > 5) return NULL;
		u->i = o16;
		if (m >= 0xc0) *hi = PD_mov_rs;
		else { EA(); *hi = PD_mov_ms; }
		return p;
	case 0xc4: case 0xc5:   // LES, LDS
		MODRM();
		if (m >= 0xc0) return NULL;
		EA();
		u->i = op == 0xc4 ? SEG_ES : SEG_DS;
		*hi = o16 ? PD_lesw : PD_lesd;
		return p;
	case 0xc8:   // ENTER (nesting level 0)
		if (p[2] & 31) return NULL;
		u->i = *(u16a *) p;
		p += 3;
		*hi = o16 ? PD_enterw : PD_enterd;
		return p;
	case 0xfa: *hi = PD_cli; return p;
	case 0x9c: *hi = o16 ? PD_pushfw : PD_pushfd; return p;
	case 0x60: *hi = o16 ? PD_pushaw : PD_pushad; return p;
	case 0x61: *hi = o16 ? PD_popaw : PD_popad; return p;
	case 0x8f:   // POP Ev
		MODRM();
		if (u->r != 0) return NULL;
		if (m >= 0xc0) { u->r = u->rm; *hi = o16 ? PD_pop_rw : PD_pop_rd; return p; }
		EA();
		*hi = o16 ? PD_pop_mw : PD_pop_md;
		return p;
	case 0xa8: case 0xa9: u->rm = 0; u->i = IMM(op & 1 ? sv : 0); *hi = PD_test_rib + (op & 1 ? sv : 0); return p;
	case 0xb0 ... 0xb7: u->rm = op & 7; u->i = *p++; *hi = PD_mov_rib; return p;
	case 0xb8 ... 0xbf: u->rm = op & 7; u->i = IMM(sv); *hi = PD_mov_rib + sv; return p;
	case 0xc0: case 0xc1: case 0xd0: case 0xd1: case 0xd2: case 0xd3: {   // shifts and rotates
		const int sz = op & 1 ? sv : 0;
		MODRM();
		static const u8 k[8] = { 3, 4, 5, 6, 0, 1, 0, 2 };   // reg field -> family (PD_SH order)
		const bool mem = m < 0xc0, cl = op >= 0xd2;
		if (mem) EA();
		u->i = op <= 0xc1 ? *p++ : 1;
		*hi = PD_shl_rib + k[u->r] * 12 + (mem ? 6 : 0) + (cl ? 3 : 0) + sz;
		return p;
	}
	case 0xc2: case 0xc3:   // RET (imm16)
		if (o16 != code16) return NULL;
		u->i = op == 0xc2 ? (p += 2, *(u16a *) (p - 2)) : 0;
		*hi = op == 0xc2 ? (o16 ? PD_reti16 : PD_reti32) : (o16 ? PD_ret16 : PD_ret32);
		*stop = true;
		return p;
	case 0xc6: case 0xc7: {   // MOV E,I
		const int sz = op & 1 ? sv : 0;
		MODRM();
		if (u->r != 0) return NULL;
		if (m >= 0xc0) *hi = PD_mov_rib + sz;
		else { EA(); *hi = PD_mov_mib + sz; }
		u->i = IMM(sz);
		return p;
	}
	case 0xe8: case 0xe9: case 0xeb:   // CALL, JMP rel
		if (o16 != code16) return NULL;
		u->i = op == 0xeb ? (u32) (s32) (s8) *p++ : o16 ? (u32) (s32) (s16) *(u16a *) p : *(u32a *) p;
		if (op != 0xeb) p += o16 ? 2 : 4;
		*hi = op == 0xe8 ? (code16 ? PD_call16 : PD_call32) : (code16 ? PD_jmp16 : PD_jmp32);
		*stop = true;
		return p;
	case 0xf6: case 0xf7: {   // TEST E,I; NOT NEG MUL IMUL DIV IDIV
		const int sz = op & 1 ? sv : 0;
		MODRM();
		const bool mem = m < 0xc0;
		if (mem) EA();
		if (u->r > 1) {
			*hi = PD_not_rb + (u->r - 2) * 6 + (mem ? 3 : 0) + sz;
			return p;
		}
		*hi = (mem ? PD_test_mib : PD_test_rib) + sz;
		u->i = IMM(sz);
		return p;
	}
	case 0x86: case 0x87: {   // XCHG E,G
		const int sz = op & 1 ? sv : 0;
		MODRM();
		if (m >= 0xc0) *hi = PD_xchg_rrb + sz;
		else { EA(); *hi = PD_xchg_mrb + sz; }
		return p;
	}
	case 0x91 ... 0x97: u->rm = 0; u->r = op & 7; *hi = PD_xchg_rrb + sv; return p;
	case 0xf5: *hi = PD_cmc; return p;
	case 0xf8: *hi = PD_clc; return p;
	case 0xf9: *hi = PD_stc; return p;
	case 0xfc: *hi = PD_cld; return p;
	case 0xfd: *hi = PD_std; return p;
	case 0xc9: *hi = o16 ? PD_leavew : PD_leaved; return p;
	case 0xe0 ... 0xe3:   // LOOPNE LOOPE LOOP JCXZ, without 67
		if (a16 != code16) return NULL;
		u->i = (u32) (s32) (s8) *p++;
		*hi = (op == 0xe2 ? PD_loop16 : op == 0xe1 ? PD_loope16 : op == 0xe0 ? PD_loopne16 : PD_jcxz16) + !code16;
		*stop = true;
		return p;
	case 0xfe: case 0xff: {   // INC DEC; FF: near CALL JMP, PUSH
		const int sz = op & 1 ? sv : 0;
		MODRM();
		const bool mem = m < 0xc0;
		if (mem) EA();
		switch (u->r) {
		case 0: *hi = (mem ? PD_inc_mb : PD_inc_rb) + sz; return p;
		case 1: *hi = (mem ? PD_dec_mb : PD_dec_rb) + sz; return p;
		}
		if (op == 0xfe || o16 != code16) { p = NULL; break; }
		switch (u->r) {
		case 2: *hi = (mem ? PD_calli_mw : PD_calli_rw) + !o16; *stop = true; return p;
		case 4: *hi = (mem ? PD_jmpi_mw : PD_jmpi_rw) + !o16; *stop = true; return p;
		case 6: if (!mem) { p = NULL; break; } *hi = o16 ? PD_push_mw : PD_push_md; return p;
		}
		p = NULL;
		break;
	}
	default:
		p = NULL;
	}
	return NULL;
#undef MODRM
#undef EA
#undef IMM
}

/* length of the instruction at p, or 0 if unknown; *xfer: it may not go on to the next one */
static int pd_len(const u8 *p0, bool code16, bool *xfer)
{
	static const u8 one[32] = {   // one-byte opcodes with ModRM, a bit each
		0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,   // 00-3f: x0-x3, x8-xb
		0x00, 0x00, 0x00, 0x00, 0x0c, 0x0a, 0x00, 0x00,   // 40-7f: 62 63, 69 6b
		0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 80-bf: 80-8f
		0xf3, 0x00, 0x0f, 0xff, 0x00, 0x00, 0xc0, 0xc0,   // c0-ff: c0 c1 c4-c7, d0-d3, d8-df, f6 f7, fe ff
	};
	const u8 *p = p0;
	bool o16 = code16, a16 = code16;
	for (;; p++) {
		if (p - p0 > 8) return 0;
		u8 b = *p;
		if (b == 0x66) o16 = !code16;
		else if (b == 0x67) a16 = !code16;
		else if (!((b & 0xe7) == 0x26 || b == 0x64 || b == 0x65 || b == 0xf0 || b == 0xf2 || b == 0xf3)) break;
	}
	const int iz = o16 ? 2 : 4;
	u8 op = *p++;
	bool modrm;
	int imm = 0;
	*xfer = false;
	if (op == 0x0f) {
		op = *p++;
		if (op >= 0x80 && op <= 0x8f) { *xfer = true; return p - p0 + iz; }
		if ((op >= 0x90 && op <= 0x9f) || op == 0xa3 || op == 0xa4 || op == 0xa5 || op == 0xab || op == 0xac ||
		    op == 0xad || op == 0xaf || (op >= 0xb0 && op <= 0xb7) || (op >= 0xba && op <= 0xbf) || op == 0xc0 ||
		    op == 0xc1 || op <= 0x03)
			modrm = true;
		else if ((op >= 0xa0 && op <= 0xa2) || (op >= 0xa8 && op <= 0xaa) || (op >= 0xc8 && op <= 0xcf) || op == 0x06 ||
			 op == 0x08 || op == 0x09 || op == 0x31)
			modrm = false;
		else
			return 0;
		if (op == 0xa4 || op == 0xac || op == 0xba) imm = 1;
		if (op <= 0x01 || op == 0xa2 || op == 0xaa) *xfer = true;   // system instructions
	} else {
		modrm = one[op >> 3] >> (op & 7) & 1;
		switch (op) {
		case 0x04: case 0x0c: case 0x14: case 0x1c: case 0x24: case 0x2c: case 0x34: case 0x3c: case 0x6a: case 0x6b:
		case 0x80: case 0x82: case 0x83: case 0xa8: case 0xb0 ... 0xb7: case 0xc0: case 0xc1: case 0xc6: case 0xd4:
		case 0xd5: case 0xe4 ... 0xe7:
			imm = 1; break;
		case 0x05: case 0x0d: case 0x15: case 0x1d: case 0x25: case 0x2d: case 0x35: case 0x3d: case 0x68: case 0x69:
		case 0x81: case 0xa9: case 0xb8 ... 0xbf: case 0xc7:
			imm = iz; break;
		case 0xa0 ... 0xa3: imm = a16 ? 2 : 4; break;
		case 0x70 ... 0x7f: case 0xe0 ... 0xe3: case 0xeb: imm = 1; *xfer = true; break;
		case 0xe8: case 0xe9: imm = iz; *xfer = true; break;
		case 0xc2: case 0xca: imm = 2; *xfer = true; break;
		case 0xc8: imm = 3; break;
		case 0xcd: imm = 1; *xfer = true; break;
		case 0x9a: case 0xea: imm = iz + 2; *xfer = true; break;
		case 0xc3: case 0xcb: case 0xcc: case 0xce: case 0xcf: case 0xf4: *xfer = true; break;
		case 0x9d: *xfer = true; break;   // POPF: IF, TF
		}
	}
	if (modrm) {
		u8 m = *p++;
		int mod = m >> 6, rm = m & 7;
		if (op == 0xf6 && ((m >> 3) & 7) < 2) imm = 1;
		if (op == 0xf7 && ((m >> 3) & 7) < 2) imm = iz;
		if (op == 0xff && ((m >> 3) & 7) >= 2 && ((m >> 3) & 7) <= 5) *xfer = true;
		if (mod != 3) {
			if (a16) {
				if (mod == 0 && rm == 6) p += 2;
				else p += mod == 1 ? 1 : mod == 2 ? 2 : 0;
			} else {
				if (rm == 4) {
					u8 sib = *p++;
					if (mod == 0 && (sib & 7) == 5) p += 4;
				}
				if (mod == 0 && rm == 5) p += 4;
				else p += mod == 1 ? 1 : mod == 2 ? 4 : 0;
			}
		}
	}
	return p - p0 + imm;
}

/* may the instruction at p write memory? (pd_classic ends the block after it then) */
static bool pd_may_write(const u8 *p)
{
	while ((*p & 0xe7) == 0x26 || (*p & 0xfc) == 0x64 || *p == 0xf0) p++;   // prefixes but REP
	u8 op = *p, m = p[1];
	switch (op) {
	case 0x8c: return m < 0xc0;   // MOV Ew,Sw to memory
	case 0x8e: case 0xc4: case 0xc5: case 0x07: case 0x17: case 0x1f: case 0xfa: case 0xfb: case 0x9e: case 0x9f:
	case 0xd7: case 0x9b: case 0xa6: case 0xa7: case 0xae: case 0xaf: case 0xac: case 0xad: case 0x27: case 0x2f:
	case 0x37: case 0x3f: case 0xd4: case 0xd5: case 0x98: case 0x99:
		return false;
	case 0xd8 ... 0xdf: return m < 0xc0;   // FPU
	case 0x0f:
		switch (m) {
		case 0xa1: case 0xa9: case 0xa2: case 0x31: case 0xb2: case 0xb4: case 0xb5: case 0x06: case 0x08:
		case 0x09: return false;
		}
		return true;
	}
	return true;
}

/* decodes the code at host into bk (instructions start before lim); returns bk's size */
static size_t pd_decode(CPUI386 *cpu, struct pd_block *bk, const u8 *host, const u8 *lim, bool code16)
{
	const u8 *p = host;
	int n = 0;
	bool stop = false;
	while (n < PD_MAX - 1 && !stop && (uintptr_t) p < (uintptr_t) lim && p - host < PD_MAXB - 15) {
		struct pd_uop *u = &bk->u[n];
		int hi;
		const u8 *q = pd_one(cpu, p, code16, u, &hi, &stop);
		u->ip = p - host;
		bk->span = u->ip;
		n++;
		if (!q) {   // unknown: pd_classic runs it in fast_ops.h
			u->h = pd_h[PD_classic];
			u->link = NULL;
			// r = 1: STI, MOV SS, POP SS (they delay interrupts: leave blocks)
			const u8 *q2 = p;
			while (q2 < p + 4 && (*q2 == 0x66 || *q2 == 0x67 || (*q2 & 0xe7) == 0x26 || (*q2 & 0xfe) == 0x64)) q2++;
			u->r = *q2 == 0xfb || *q2 == 0x17 || (*q2 == 0x8e && ((q2[1] >> 3) & 7) == SEG_SS);
			bool xfer;
			const int len = u->r ? 0 : pd_len(p, code16, &xfer);
			u->rm = !len || pd_may_write(p);
			if (!len || xfer || u->rm) break;
			p += len;
			continue;
		}
		u->h = pd_h[hi];
		p = q;
	}
	bk->host = host;
	bk->code16 = code16;
	bk->dlo = bk->dhi = 0;
	if (!n) {
		bk->n = bk->nbytes = bk->span = 0;
	} else {
		struct pd_uop *e = &bk->u[n++];
		e->h = pd_h[PD_end];
		e->link = NULL;
		e->ip = p - host;
		bk->n = n;
		bk->nbytes = p - host;
		memcpy((u8 *) PD_CODE(bk), host, bk->nbytes);
	}

	const uintptr_t al = __alignof__(struct pd_block) - 1;
	return (((uintptr_t) PD_CODE(bk) + bk->nbytes + al) & ~al) - (uintptr_t) bk;
}

/* mark bk's lines in pd_codeln (from 3 bytes before: a 4-byte store there reaches the code) */
static void pd_lines(CPUI386 *cpu, const struct pd_block *bk)
{
	const uword s = bk->host - cpu->phys_mem;
	if (bk->nbytes)
		for (uword a = s > 3 ? s - 3 : 0, e = s + bk->nbytes; a < e; a = (a | 127) + 1)
			if (a < pd_ram) pd_codeln[a >> 12] |= 1u << ((a >> 7) & 31);
}

#define PD_MOST (sizeof(struct pd_block) + PD_MAX * sizeof(struct pd_uop) + PD_MAX * 15 + 16)

/* a new block for the code at host */
static struct pd_block *pd_build(CPUI386 *cpu, const u8 *host, const u8 *lim, bool code16)
{
	if (pd_free + PD_MOST > pd_arena + FAST_PD_SIZE) pd_flush();
	struct pd_block *bk = (struct pd_block *) pd_free;
	const size_t size = pd_decode(cpu, bk, host, lim, code16);
	bk->cap = size - sizeof(struct pd_block);
	pd_free += size;
	unsigned hh = pd_hash_of(host);
	bk->hnext = pd_hash[hh];
	pd_hash[hh] = bk;
	const uword ln = (uword) (host - cpu->phys_mem) >> 7;
	if (ln < pd_ram >> 7) {
		bk->lnext = pd_lnblk[ln];
		pd_lnblk[ln] = bk;
	}
	pd_lines(cpu, bk);
	return bk;
}

/* decode bk again in place, if the new code fits */
static bool pd_redo(CPUI386 *cpu, struct pd_block *bk, const u8 *lim)
{
	static union { struct pd_block b; u8 room[PD_MOST]; } t;
	const size_t size = pd_decode(cpu, &t.b, bk->host, lim, bk->code16);
	if (size - sizeof(struct pd_block) > bk->cap) return false;
	struct pd_block *next = bk->hnext, *ln = bk->lnext;
	const u16 cap = bk->cap;
	memcpy(bk, &t.b, size);
	bk->hnext = next;
	bk->lnext = ln;
	bk->cap = cap;
	pd_lines(cpu, bk);
	return true;
}

/* the block for the code at host as it is now, made if needed. Blocks of older code stay (programs
 * and overlays take turns at the same addresses). */
static struct pd_block *pd_get(CPUI386 *cpu, const u8 *host, const u8 *lim, bool code16)
{
	struct pd_block *old = NULL;
	for (struct pd_block *bk = pd_hash[pd_hash_of(host)]; bk; bk = bk->hnext)
		if (bk->host == host && bk->code16 == code16 && (uintptr_t) (host + bk->span) < (uintptr_t) lim) {
			if (pd_same(bk)) return bk;
			if (!old) old = bk;
		}
	if (old && pd_redo(cpu, old, lim)) return old;
	return pd_build(cpu, host, lim, code16);
}


/* A uop stored n bytes at RAM address a, in a line with blocks' code: mark the blocks it overlaps.
 * If one is the block running (cur, at uop u), it ends after u and is decoded again next time. */
static noinline void pd_wrote(uword a, int n, struct pd_block *cur, const struct pd_uop *u, const void *leave,
			      const u8 *phys)
{
	const uword l1 = (a + n - 1) >> 7;
	for (uword l = a > PD_MAXB ? (a - PD_MAXB) >> 7 : 0; l <= l1 && l < pd_ram >> 7; l++)
		for (struct pd_block *bk = pd_lnblk[l]; bk; bk = bk->lnext) {
			const uword b = bk->host - phys;
			if (a + n <= b || a >= b + bk->nbytes) continue;
			if (bk == cur) {
				((struct pd_uop *) u + 1)->h = leave;
				((u8 *) PD_CODE(bk))[0] ^= 0xff;
				bk->dep = pd_ep - 1;
			} else {   // the bytes written, for pd_patch
				const uword lo = a > b ? a - b : 0, hi = a + n - b < bk->nbytes ? a + n - b : bk->nbytes;
				if (bk->ep == pd_ep) {
					bk->dep = pd_ep;
					bk->dlo = lo;
					bk->dhi = hi;
				} else if (bk->dep == pd_ep && bk->dhi) {
					if (lo < bk->dlo) bk->dlo = lo;
					if (hi > bk->dhi) bk->dhi = hi;
				}
			}
			bk->ep = pd_ep - 1;
		}
}

/* Only uops wrote bk's code, at [dlo, dhi): decode those instructions again in place.
 * False if they no longer fit (other length, now a jump): compare the block in full. */
static bool pd_patch(CPUI386 *cpu, struct pd_block *bk)
{
	for (int k = 0; k < bk->n - 1; k++) {
		struct pd_uop *u = &bk->u[k];
		const uword s = u->ip, e = bk->u[k + 1].ip;
		if (e <= bk->dlo || s >= bk->dhi) continue;
		if (u->h == pd_h[PD_classic] || u->h == pd_h[PD_leave] || u->h == pd_h[PD_end]) return false;
		struct pd_uop t;
		int hi;
		bool stop;
		const u8 *q = pd_one(cpu, bk->host + s, bk->code16, &t, &hi, &stop);
		if (!q || (uword) (q - bk->host) != e || (stop && k < bk->n - 2)) return false;
		t.h = pd_h[hi];
		t.ip = s;
		*u = t;
	}
	memcpy((u8 *) PD_CODE(bk) + bk->dlo, bk->host + bk->dlo, bk->dhi - bk->dlo);
	bk->dhi = 0;
	return true;
}

