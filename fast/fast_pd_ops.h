/*
 * Uop handlers (fast_pd.h), included in fast_exec. pu: the uop, bh: its block's code, bk: the block.
 * Each handler runs the next uop; the end, jumps, calls and returns go to the next block (pd_go).
 */

	// FAST_VERIFY checks each uop as an instruction
#ifdef FAST_VERIFY
#define PD_BEGIN do { ins = bh + pu->ip; FV_BEGIN; } while (0)
#else
#define PD_BEGIN do { } while (0)
#endif
#define PD_NEXTIP (bh + pu[1].ip)
#define PD_NEXT do { FV_END(EIP_OF(PD_NEXTIP)); --steps; pu++; goto *pu->h; } while (0)
#define PD_JUMP(t) do { pc = (t); FV_END(EIP_OF(pc)); --steps; lk = &((struct pd_uop *) pu)->link; goto pd_go; } while (0)
#define PD_EA(o) uword o = (*pu->b + (*pu->x << pu->scl) + pu->d) & (0xffffffffu >> pu->ams)
	// as FPTR_IO (not RAM: to MISS, mlin and msize set)
#define PD_PTR(p, sg, off, size, wr, MISS) do { \
		const int _sg = (sg); \
		if (unlikely(nullsegs) && (nullsegs & (1 << _sg))) goto pd_slow; \
		uword _lin = cpu->seg[_sg].base + (off); \
		struct ftlb_entry *_e = &ftlb[(_lin >> 12) & (FTLB_N - 1)]; \
		if (likely(((wr) ? _e->wtag : _e->rtag) == ((_lin + (size) - 1) >> 12))) \
			p = (u8 *) (uintptr_t) (_lin + _e->delta); \
		else if (!(p = ftlb_miss(cpu, _lin, (size), (wr)))) { \
			mlin = _lin; \
			msize = (size); \
			goto MISS; \
		} \
		if (wr) PD_WROTE(p, size); \
	} while (0)
	// a store to a line with blocks' code marks the blocks it overlaps
#define PD_WROTE(p, size) do { \
		uword _pp = (uword) ((p) - cpu->phys_mem), _pe = _pp + (size) - 1; \
		if (unlikely(_pp < pd_ram && ((pd_codeln[_pp >> 12] >> ((_pp >> 7) & 31) & 1) || \
					      ((size) > 4 && (pd_codeln[_pe >> 12] >> ((_pe >> 7) & 31) & 1))))) \
			pd_wrote(_pp, (size) > 4 ? (size) : 4, pd_cur, pu, pd_tab[PD_leave], cpu->phys_mem); \
	} while (0)
#define PD_MEM(p, size, wr) PD_EA(_o); u8 *p; PD_PTR(p, pu->sg, _o, size, wr, pd_slow)
#define PD_STACK(s, d, size, wr) u8 *s; do { \
		uword _sp = (REGi(4) + (d)) & sp_mask; \
		if ((size) > 4 && _sp > sp_mask - ((size) - 1)) goto pd_slow;   /* slots wrapping around: tiny386 */ \
		PD_PTR(s, SEG_SS, _sp, size, wr, pd_slow); \
	} while (0)

	// ---- MOV
#define PD_MOV(SFX, SZ, LR, SR, LM, SM) \
pd_mov_rr##SFX: { PD_BEGIN; SR(pu->rm, LR(pu->r)); PD_NEXT; } \
pd_mov_rm##SFX: { PD_BEGIN; PD_EA(_o); u8 *p; PD_PTR(p, pu->sg, _o, SZ, 0, pd_mmio_ld); SR(pu->r, LM(p)); PD_NEXT; } \
pd_mov_mr##SFX: { PD_BEGIN; PD_EA(_o); mval = LR(pu->r); u8 *p; PD_PTR(p, pu->sg, _o, SZ, 1, pd_mmio_st); SM(p, mval); PD_NEXT; } \
pd_mov_ri##SFX: { PD_BEGIN; SR(pu->rm, pu->i); PD_NEXT; } \
pd_mov_mi##SFX: { PD_BEGIN; PD_EA(_o); mval = pu->i; u8 *p; PD_PTR(p, pu->sg, _o, SZ, 1, pd_mmio_st); SM(p, mval); PD_NEXT; }
	PD_MOV(b, 1, fr8, fw8, fm8, fs8)
	PD_MOV(w, 2, lreg16, sreg16, fm16, fs16)
	PD_MOV(d, 4, lreg32, sreg32, fm32, fs32)
pd_mmio_st: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 1);
	if (pa == (uword) -1) goto pd_slow;
	FV_SKIP;
	fast_io_write(cpu, pa, msize, mval);
	PD_NEXT; }
pd_mmio_ld: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 0);
	if (pa == (uword) -1) goto pd_slow;
	FV_SKIP;
	u32 v = fast_io_read(cpu, pa, msize);
	if (msize == 1) fw8(pu->r, v); else if (msize == 2) sreg16(pu->r, v); else sreg32(pu->r, v);
	PD_NEXT; }

	// ---- ALU, TEST
#define PD_ALU1(N, SFX, SZ, OP, LR, SR, LM, SM, T, WR) \
pd_##N##_rr##SFX: { PD_BEGIN; int _a = pu->rm, _b = pu->r; OP(_a, _b, LR, SR, LR, SR) PD_NEXT; } \
pd_##N##_rm##SFX: { PD_BEGIN; PD_MEM(p, SZ, 0); int _a = pu->r; OP(_a, p, LR, SR, LM, SM) PD_NEXT; } \
pd_##N##_mr##SFX: { PD_BEGIN; PD_MEM(p, SZ, WR); int _b = pu->r; OP(p, _b, LM, SM, LR, SR) PD_NEXT; } \
pd_##N##_ri##SFX: { PD_BEGIN; int _a = pu->rm; T _i = pu->i; OP(_a, _i, LR, SR, limm, 0) PD_NEXT; } \
pd_##N##_mi##SFX: { PD_BEGIN; PD_MEM(p, SZ, WR); T _i = pu->i; OP(p, _i, LM, SM, limm, 0) PD_NEXT; }
#define PD_ALU(N, OPb, OPw, OPd, WR) \
	PD_ALU1(N, b, 1, OPb, fr8, fw8, fm8, fs8, u8, WR) \
	PD_ALU1(N, w, 2, OPw, lreg16, sreg16, fm16, fs16, u16, WR) \
	PD_ALU1(N, d, 4, OPd, lreg32, sreg32, fm32, fs32, u32, WR)
	PD_ALU(add, ADDb, ADDw, ADDd, 1)
	PD_ALU(or, ORb, ORw, ORd, 1)
	PD_ALU(adc, ADCb, ADCw, ADCd, 1)
	PD_ALU(sbb, SBBb, SBBw, SBBd, 1)
	PD_ALU(and, ANDb, ANDw, ANDd, 1)
	PD_ALU(sub, SUBb, SUBw, SUBd, 1)
	PD_ALU(xor, XORb, XORw, XORd, 1)
	PD_ALU(cmp, FCMPb, FCMPw, FCMPd, 0)
	PD_ALU(test, FTESTb, FTESTw, FTESTd, 0)

	// ---- INC, DEC
#define PD_INCDEC1(N, SFX, SZ, OP, LR, SR, LM, SM) \
pd_##N##_r##SFX: { PD_BEGIN; int _a = pu->rm; OP(_a, LR, SR) PD_NEXT; } \
pd_##N##_m##SFX: { PD_BEGIN; PD_MEM(p, SZ, 1); OP(p, LM, SM) PD_NEXT; }
	PD_INCDEC1(inc, b, 1, INCb, fr8, fw8, fm8, fs8)
	PD_INCDEC1(inc, w, 2, INCw, lreg16, sreg16, fm16, fs16)
	PD_INCDEC1(inc, d, 4, INCd, lreg32, sreg32, fm32, fs32)
	PD_INCDEC1(dec, b, 1, DECb, fr8, fw8, fm8, fs8)
	PD_INCDEC1(dec, w, 2, DECw, lreg16, sreg16, fm16, fs16)
	PD_INCDEC1(dec, d, 4, DECd, lreg32, sreg32, fm32, fs32)

	// ---- the stack
pd_push_rw: { PD_BEGIN; PD_STACK(s, -2, 2, 1); u16 _v = lreg16(pu->r); SP_ADD(-2); fs16(s, _v); PD_NEXT; }
pd_push_rd: { PD_BEGIN; PD_STACK(s, -4, 4, 1); u32 _v = lreg32(pu->r); SP_ADD(-4); fs32(s, _v); PD_NEXT; }
pd_pop_rw: { PD_BEGIN; PD_STACK(s, 0, 2, 0); u16 _v = fm16(s); SP_ADD(2); sreg16(pu->r, _v); PD_NEXT; }
pd_pop_rd: { PD_BEGIN; PD_STACK(s, 0, 4, 0); u32 _v = fm32(s); SP_ADD(4); sreg32(pu->r, _v); PD_NEXT; }
pd_push_iw: { PD_BEGIN; PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, pu->i); PD_NEXT; }
pd_push_id: { PD_BEGIN; PD_STACK(s, -4, 4, 1); SP_ADD(-4); fs32(s, pu->i); PD_NEXT; }
pd_push_mw: { PD_BEGIN; PD_MEM(p, 2, 0); u16 _v = fm16(p); PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, _v); PD_NEXT; }
pd_push_md: { PD_BEGIN; PD_MEM(p, 4, 0); u32 _v = fm32(p); PD_STACK(s, -4, 4, 1); SP_ADD(-4); fs32(s, _v); PD_NEXT; }

	// ---- LEA, MOVZX, MOVSX, CBW, CWD
pd_leaw: { PD_BEGIN; PD_EA(_o); sreg16(pu->r, _o); PD_NEXT; }
pd_lead: { PD_BEGIN; PD_EA(_o); sreg32(pu->r, _o); PD_NEXT; }
#define PD_MOVX(N, T, LR, LM, SZ, SR, EXT) \
pd_##N##_r: { PD_BEGIN; T _v = LR(pu->rm); SR(pu->r, EXT(_v)); PD_NEXT; } \
pd_##N##_m: { PD_BEGIN; PD_MEM(p, SZ, 0); T _v = LM(p); SR(pu->r, EXT(_v)); PD_NEXT; }
#define PD_ZX(v) (v)
	PD_MOVX(zbw, u8, fr8, fm8, 1, sreg16, PD_ZX)
	PD_MOVX(zbd, u8, fr8, fm8, 1, sreg32, PD_ZX)
	PD_MOVX(zwd, u16, lreg16, fm16, 2, sreg32, PD_ZX)
	PD_MOVX(sbw, u8, fr8, fm8, 1, sreg16, sext8)
	PD_MOVX(sbd, u8, fr8, fm8, 1, sreg32, sext8)
	PD_MOVX(swd, u16, lreg16, fm16, 2, sreg32, sext16)
pd_cbw: { PD_BEGIN; sreg16(0, sext8(lreg8(0))); PD_NEXT; }
pd_cwde: { PD_BEGIN; sreg32(0, sext16(lreg16(0))); PD_NEXT; }
pd_cwd: { PD_BEGIN; sreg16(2, sext16(-(sext16(lreg16(0)) >> 31))); PD_NEXT; }
pd_cdq: { PD_BEGIN; sreg32(2, sext32(-(sext32(lreg32(0)) >> 31))); PD_NEXT; }
pd_nop: { PD_BEGIN; PD_NEXT; }

	// ---- shifts and rotates: by an immediate (or 1), by CL
#define PD_SHIFT1(N, SFX, SZ, OP, LR, SR, LM, SM) \
pd_##N##_ri##SFX: { PD_BEGIN; int _a = pu->rm; u8 _n = pu->i; OP(_a, _n, LR, SR, limm, 0) PD_NEXT; } \
pd_##N##_rc##SFX: { PD_BEGIN; int _a = pu->rm; u8 _n = fr8(1); OP(_a, _n, LR, SR, limm, 0) PD_NEXT; } \
pd_##N##_mi##SFX: { PD_BEGIN; PD_MEM(p, SZ, 1); u8 _n = pu->i; OP(p, _n, LM, SM, limm, 0) PD_NEXT; } \
pd_##N##_mc##SFX: { PD_BEGIN; PD_MEM(p, SZ, 1); u8 _n = fr8(1); OP(p, _n, LM, SM, limm, 0) PD_NEXT; }
#define PD_SHIFT(N, OP) \
	PD_SHIFT1(N, b, 1, OP##b, fr8, fw8, fm8, fs8) \
	PD_SHIFT1(N, w, 2, OP##w, lreg16, sreg16, fm16, fs16) \
	PD_SHIFT1(N, d, 4, OP##d, lreg32, sreg32, fm32, fs32)
	PD_SHIFT(shl, SHL)
	PD_SHIFT(shr, SHR)
	PD_SHIFT(sar, SAR)
	PD_SHIFT(rol, ROL)
	PD_SHIFT(ror, ROR)
	PD_SHIFT(rcl, RCL)
	PD_SHIFT(rcr, RCR)

	// ---- NOT NEG MUL IMUL DIV IDIV (#DE at the instruction)
#define PD_G3_1(N, SFX, SZ, OP, LR, SR, LM, SM, WR, PRE) \
pd_##N##_r##SFX: { PD_BEGIN; PRE; int _a = pu->rm; OP(_a, LR, SR) PD_NEXT; } \
pd_##N##_m##SFX: { PD_BEGIN; PD_MEM(p, SZ, WR); PRE; OP(p, LM, SM) PD_NEXT; }
#define PD_G3(N, OP, WR, PRE) \
	PD_G3_1(N, b, 1, OP##b, fr8, fw8, fm8, fs8, WR, PRE) \
	PD_G3_1(N, w, 2, OP##w, lreg16, sreg16, fm16, fs16, WR, PRE) \
	PD_G3_1(N, d, 4, OP##d, lreg32, sreg32, fm32, fs32, WR, PRE)
#define PD_AT_INS (cpu->ip = EIP_OF(bh + pu->ip))
	PD_G3(not, NOT, 1, )
	PD_G3(neg, NEG, 1, )
	PD_G3(mul, MUL, 0, )
	PD_G3(imul, IMUL, 0, )
	PD_G3(div, DIV, 0, PD_AT_INS)
	PD_G3(idiv, IDIV, 0, PD_AT_INS)

	// ---- XCHG, SETcc, flags, LEAVE
#define PD_XCHG(SFX, SZ, OP, LR, SR, LM, SM) \
pd_xchg_rr##SFX: { PD_BEGIN; int _a = pu->rm, _b = pu->r; OP(_a, _b, LR, SR, LR, SR) PD_NEXT; } \
pd_xchg_mr##SFX: { PD_BEGIN; PD_MEM(p, SZ, 1); int _b = pu->r; OP(p, _b, LM, SM, LR, SR) PD_NEXT; }
	PD_XCHG(b, 1, XCHGb, fr8, fw8, fm8, fs8)
	PD_XCHG(w, 2, XCHGw, lreg16, sreg16, fm16, fs16)
	PD_XCHG(d, 4, XCHGd, lreg32, sreg32, fm32, fs32)
pd_setcc_r: { PD_BEGIN; int _c = fast_cond(cpu, pu->i); fw8(pu->rm, _c); PD_NEXT; }
pd_setcc_m: { PD_BEGIN; int _c = fast_cond(cpu, pu->i); PD_MEM(p, 1, 1); fs8(p, _c); PD_NEXT; }
pd_clc: { PD_BEGIN; CLC() PD_NEXT; }
pd_stc: { PD_BEGIN; STC() PD_NEXT; }
pd_cmc: { PD_BEGIN; CMC() PD_NEXT; }
pd_cld: { PD_BEGIN; CLD() PD_NEXT; }
pd_std: { PD_BEGIN; STD() PD_NEXT; }
	// ---- MOVS STOS LODS without REP (MMIO: STOS and LODS)
#define PD_STR1(A, SFX, N, LR, SR, LM, SM, LI, SI) \
pd_lods##A##SFX: { PD_BEGIN; u8 *p; PD_PTR(p, pu->sg, LI(6), N, 0, pd_lods_io); SR(0, LM(p)); \
	SI(6, LI(6) + ((cpu->flags & DF) ? -N : N)); PD_NEXT; } \
pd_stos##A##SFX: { PD_BEGIN; mval = LR(0); u8 *p; PD_PTR(p, SEG_ES, LI(7), N, 1, pd_stos_io); SM(p, mval); \
	SI(7, LI(7) + ((cpu->flags & DF) ? -N : N)); PD_NEXT; } \
pd_movs##A##SFX: { PD_BEGIN; u8 *s, *d; PD_PTR(s, pu->sg, LI(6), N, 0, pd_slow); PD_PTR(d, SEG_ES, LI(7), N, 1, pd_slow); \
	SM(d, LM(s)); const int _dir = (cpu->flags & DF) ? -N : N; SI(6, LI(6) + _dir); SI(7, LI(7) + _dir); PD_NEXT; }
	PD_STR1(16, b, 1, fr8, fw8, fm8, fs8, lreg16, sreg16)
	PD_STR1(16, w, 2, lreg16, sreg16, fm16, fs16, lreg16, sreg16)
	PD_STR1(16, d, 4, lreg32, sreg32, fm32, fs32, lreg16, sreg16)
	PD_STR1(32, b, 1, fr8, fw8, fm8, fs8, lreg32, sreg32)
	PD_STR1(32, w, 2, lreg16, sreg16, fm16, fs16, lreg32, sreg32)
	PD_STR1(32, d, 4, lreg32, sreg32, fm32, fs32, lreg32, sreg32)
pd_stos_io: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 1);
	if (pa == (uword) -1) goto pd_slow;
	FV_SKIP;
	fast_io_write(cpu, pa, msize, mval);
	const int _dir = (cpu->flags & DF) ? -msize : msize;
	if (pu->h == pd_tab[PD_stos16b] || pu->h == pd_tab[PD_stos16w] || pu->h == pd_tab[PD_stos16d]) sreg16(7, lreg16(7) + _dir);
	else sreg32(7, lreg32(7) + _dir);
	PD_NEXT; }
pd_lods_io: {
	uword pa = fast_mmio_addr(cpu, mlin, msize, 0);
	if (pa == (uword) -1) goto pd_slow;
	FV_SKIP;
	u32 v = fast_io_read(cpu, pa, msize);
	if (msize == 1) fw8(0, v); else if (msize == 2) sreg16(0, v); else sreg32(0, v);
	const int _dir = (cpu->flags & DF) ? -msize : msize;
	if (pu->h == pd_tab[PD_lods16b] || pu->h == pd_tab[PD_lods16w] || pu->h == pd_tab[PD_lods16d]) sreg16(6, lreg16(6) + _dir);
	else sreg32(6, lreg32(6) + _dir);
	PD_NEXT; }
	// ---- IN, OUT (tiny386 when IOPL forbids)
#define PD_IO(N, PORT) \
pd_in_##N##b: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; fw8(0, cpu->cb.io_read8(cpu->cb.io, PORT)); PD_NEXT; } \
pd_in_##N##w: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; sreg16(0, cpu->cb.io_read16(cpu->cb.io, PORT)); PD_NEXT; } \
pd_in_##N##d: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; sreg32(0, cpu->cb.io_read32(cpu->cb.io, PORT)); PD_NEXT; } \
pd_out_##N##b: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; cpu->cb.io_write8(cpu->cb.io, PORT, fr8(0)); PD_NEXT; } \
pd_out_##N##w: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; cpu->cb.io_write16(cpu->cb.io, PORT, lreg16(0)); PD_NEXT; } \
pd_out_##N##d: { PD_BEGIN; if (!IO_ALLOWED) goto pd_slow; FV_SKIP; cpu->cb.io_write32(cpu->cb.io, PORT, lreg32(0)); PD_NEXT; }
	PD_IO(i, pu->i)
	PD_IO(dx, lreg16(2))
	// ---- segment registers (protected mode: set_seg), PUSHA POPA ENTER, POP to memory
#define PD_LOAD_SEG(sg, v) do { \
		if (PROTECTED) { if (!FAST_LOAD_SEG((sg), (v))) goto pd_slow; } \
		else { cpu->seg[sg].sel = (v); cpu->seg[sg].base = (v) << 4; cpu->seg[sg].limit = 0xffff; cpu->seg[sg].flags = 0; } \
	} while (0)
pd_push_sw: { PD_BEGIN; PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, cpu->seg[pu->r].sel); PD_NEXT; }
pd_push_sd: { PD_BEGIN; PD_STACK(s, -4, 2, 1); SP_ADD(-4); fs16(s, cpu->seg[pu->r].sel); PD_NEXT; }
pd_pop_sw: { PD_BEGIN; PD_STACK(s, 0, 2, 0); u16 _sel = fm16(s); PD_LOAD_SEG(pu->r, _sel); SP_ADD(2); PD_NEXT; }
pd_pop_sd: { PD_BEGIN; PD_STACK(s, 0, 2, 0); u16 _sel = fm16(s); PD_LOAD_SEG(pu->r, _sel); SP_ADD(4); PD_NEXT; }
pd_mov_sr: { PD_BEGIN; u16 _sel = lreg16(pu->rm); PD_LOAD_SEG(pu->r, _sel); PD_NEXT; }
pd_mov_sm: { PD_BEGIN; PD_MEM(p, 2, 0); u16 _sel = fm16(p); PD_LOAD_SEG(pu->r, _sel); PD_NEXT; }
pd_mov_rs: { PD_BEGIN; if (pu->i) sreg16(pu->rm, cpu->seg[pu->r].sel); else sreg32(pu->rm, cpu->seg[pu->r].sel); PD_NEXT; }
pd_mov_ms: { PD_BEGIN; PD_MEM(p, 2, 1); fs16(p, cpu->seg[pu->r].sel); PD_NEXT; }
pd_lesw: { PD_BEGIN; PD_MEM(p, 4, 0); u16 _off = fm16(p), _sel = fm16(p + 2); PD_LOAD_SEG(pu->i, _sel); sreg16(pu->r, _off); PD_NEXT; }
pd_lesd: { PD_BEGIN; PD_MEM(p, 6, 0); u32 _off = fm32(p); u16 _sel = fm16(p + 4); PD_LOAD_SEG(pu->i, _sel); sreg32(pu->r, _off); PD_NEXT; }
pd_enterw: { PD_BEGIN; PD_STACK(s, -2, 2, 1); uword _sp = REGi(4); set_sp(_sp - 2 - (u16) pu->i, sp_mask);
	fs16(s, lreg16(5)); sreg16(5, (_sp - 2) & sp_mask); PD_NEXT; }
pd_enterd: { PD_BEGIN; PD_STACK(s, -4, 4, 1); uword _sp = REGi(4); set_sp(_sp - 4 - (u16) pu->i, sp_mask);
	fs32(s, lreg32(5)); sreg32(5, (_sp - 4) & sp_mask); PD_NEXT; }
pd_pushaw: { PD_BEGIN; PD_STACK(s, -16, 16, 1); uword _sp = REGi(4);
	for (int i = 0; i < 8; i++) fs16(s + 14 - 2 * i, i == 4 ? _sp : lreg16(i));
	SP_ADD(-16); PD_NEXT; }
pd_pushad: { PD_BEGIN; PD_STACK(s, -32, 32, 1); uword _sp = REGi(4);
	for (int i = 0; i < 8; i++) fs32(s + 28 - 4 * i, i == 4 ? _sp : lreg32(i));
	SP_ADD(-32); PD_NEXT; }
pd_popaw: { PD_BEGIN; PD_STACK(s, 0, 16, 0); for (int i = 0; i < 8; i++) if (i != 4) sreg16(i, fm16(s + 14 - 2 * i)); SP_ADD(16); PD_NEXT; }
pd_popad: { PD_BEGIN; PD_STACK(s, 0, 32, 0); for (int i = 0; i < 8; i++) if (i != 4) sreg32(i, fm32(s + 28 - 4 * i)); SP_ADD(32); PD_NEXT; }
pd_pop_mw: { PD_BEGIN; uword _sp0 = REGi(4); PD_STACK(s, 0, 2, 0); u16 _v = fm16(s);   // address with SP moved on
	SP_ADD(2); PD_EA(_o); set_sp(_sp0, sp_mask); u8 *p; PD_PTR(p, pu->sg, _o, 2, 1, pd_slow); fs16(p, _v); SP_ADD(2); PD_NEXT; }
pd_pop_md: { PD_BEGIN; uword _sp0 = REGi(4); PD_STACK(s, 0, 4, 0); u32 _v = fm32(s);
	SP_ADD(4); PD_EA(_o); set_sp(_sp0, sp_mask); u8 *p; PD_PTR(p, pu->sg, _o, 4, 1, pd_slow); fs32(p, _v); SP_ADD(4); PD_NEXT; }
pd_cli: { PD_BEGIN; if (get_IOPL(cpu) < cpu->cpl) goto pd_slow; cpu->flags &= ~IF; PD_NEXT; }
pd_pushfw: { PD_BEGIN; if (!V86_IOPL3) goto pd_slow; PD_STACK(s, -2, 2, 1); refresh_flags(cpu); cpu->cc.mask = 0;
	SP_ADD(-2); fs16(s, cpu->flags); PD_NEXT; }
pd_pushfd: { PD_BEGIN; if (!V86_IOPL3) goto pd_slow; PD_STACK(s, -4, 4, 1); refresh_flags(cpu); cpu->cc.mask = 0;
	SP_ADD(-4); fs32(s, cpu->flags & ~(RF | VM)); PD_NEXT; }
pd_leavew: { PD_BEGIN; uword _bp = REGi(5) & sp_mask; u8 *p; PD_PTR(p, SEG_SS, _bp, 2, 0, pd_slow);
	set_sp(REGi(5) + 2, sp_mask); sreg16(5, fm16(p)); PD_NEXT; }
pd_leaved: { PD_BEGIN; uword _bp = REGi(5) & sp_mask; u8 *p; PD_PTR(p, SEG_SS, _bp, 4, 0, pd_slow);
	set_sp(REGi(5) + 4, sp_mask); sreg32(5, fm32(p)); PD_NEXT; }

	// ---- IMUL, SHLD, SHRD
pd_imul2_rw: { PD_BEGIN; int _a = pu->r, _b = pu->rm; IMUL2w(_a, _b, lreg16, sreg16, lreg16, sreg16) PD_NEXT; }
pd_imul2_rd: { PD_BEGIN; int _a = pu->r, _b = pu->rm; IMUL2d(_a, _b, lreg32, sreg32, lreg32, sreg32) PD_NEXT; }
pd_imul2_mw: { PD_BEGIN; PD_MEM(p, 2, 0); int _a = pu->r; IMUL2w(_a, p, lreg16, sreg16, fm16, fs16) PD_NEXT; }
pd_imul2_md: { PD_BEGIN; PD_MEM(p, 4, 0); int _a = pu->r; IMUL2d(_a, p, lreg32, sreg32, fm32, fs32) PD_NEXT; }
pd_imul3_rw: { PD_BEGIN; int _a = pu->r, _b = pu->rm; u16 _i = pu->i; IMUL2wIw(_a, _b, _i, lreg16, sreg16, lreg16, sreg16) PD_NEXT; }
pd_imul3_rd: { PD_BEGIN; int _a = pu->r, _b = pu->rm; u32 _i = pu->i; IMUL2dId(_a, _b, _i, lreg32, sreg32, lreg32, sreg32) PD_NEXT; }
pd_imul3_mw: { PD_BEGIN; PD_MEM(p, 2, 0); int _a = pu->r; u16 _i = pu->i; IMUL2wIw(_a, p, _i, lreg16, sreg16, fm16, fs16) PD_NEXT; }
pd_imul3_md: { PD_BEGIN; PD_MEM(p, 4, 0); int _a = pu->r; u32 _i = pu->i; IMUL2dId(_a, p, _i, lreg32, sreg32, fm32, fs32) PD_NEXT; }
#define PD_SHxD(N, OP) \
pd_##N##_rw: { PD_BEGIN; int _a = pu->rm, _b = pu->r; u8 _c = pu->i; OP##w(_a, _b, _c, lreg16, sreg16, lreg16, sreg16, limm, 0) PD_NEXT; } \
pd_##N##_rd: { PD_BEGIN; int _a = pu->rm, _b = pu->r; u8 _c = pu->i; OP##d(_a, _b, _c, lreg32, sreg32, lreg32, sreg32, limm, 0) PD_NEXT; } \
pd_##N##_mw: { PD_BEGIN; PD_MEM(p, 2, 1); int _b = pu->r; u8 _c = pu->i; OP##w(p, _b, _c, fm16, fs16, lreg16, sreg16, limm, 0) PD_NEXT; } \
pd_##N##_md: { PD_BEGIN; PD_MEM(p, 4, 1); int _b = pu->r; u8 _c = pu->i; OP##d(p, _b, _c, fm32, fs32, lreg32, sreg32, limm, 0) PD_NEXT; }
	PD_SHxD(shld, SHLD)
	PD_SHxD(shrd, SHRD)

	// ---- jumps, calls, returns (16-bit code wraps at 64K)
#define PD_REL16 ((const u8 *) (ipd + ((EIP_OF(PD_NEXTIP) + pu->i) & 0xffff)))
#define PD_REL32 (PD_NEXTIP + (sword) pu->i)
#define PD_JCC(C) \
pd_j16_##C: { PD_BEGIN; if (fast_cond(cpu, 0x##C)) PD_JUMP(PD_REL16); PD_NEXT; } \
pd_j32_##C: { PD_BEGIN; if (fast_cond(cpu, 0x##C)) PD_JUMP(PD_REL32); PD_NEXT; }
	PD_JCC(0) PD_JCC(1) PD_JCC(2) PD_JCC(3) PD_JCC(4) PD_JCC(5) PD_JCC(6) PD_JCC(7)
	PD_JCC(8) PD_JCC(9) PD_JCC(a) PD_JCC(b) PD_JCC(c) PD_JCC(d) PD_JCC(e) PD_JCC(f)
pd_loop16: { PD_BEGIN; u16 _c = lreg16(1) - 1; sreg16(1, _c); if (_c) PD_JUMP(PD_REL16); PD_NEXT; }
pd_loop32: { PD_BEGIN; u32 _c = lreg32(1) - 1; sreg32(1, _c); if (_c) PD_JUMP(PD_REL32); PD_NEXT; }
pd_loope16: { PD_BEGIN; u16 _c = lreg16(1) - 1; sreg16(1, _c); if (_c && get_ZF(cpu)) PD_JUMP(PD_REL16); PD_NEXT; }
pd_loope32: { PD_BEGIN; u32 _c = lreg32(1) - 1; sreg32(1, _c); if (_c && get_ZF(cpu)) PD_JUMP(PD_REL32); PD_NEXT; }
pd_loopne16: { PD_BEGIN; u16 _c = lreg16(1) - 1; sreg16(1, _c); if (_c && !get_ZF(cpu)) PD_JUMP(PD_REL16); PD_NEXT; }
pd_loopne32: { PD_BEGIN; u32 _c = lreg32(1) - 1; sreg32(1, _c); if (_c && !get_ZF(cpu)) PD_JUMP(PD_REL32); PD_NEXT; }
pd_jcxz16: { PD_BEGIN; if (lreg16(1) == 0) PD_JUMP(PD_REL16); PD_NEXT; }
pd_jcxz32: { PD_BEGIN; if (lreg32(1) == 0) PD_JUMP(PD_REL32); PD_NEXT; }
pd_jmp16: { PD_BEGIN; PD_JUMP(PD_REL16); }
pd_jmp32: { PD_BEGIN; PD_JUMP(PD_REL32); }
pd_call16: { PD_BEGIN; PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, EIP_OF(PD_NEXTIP)); PD_JUMP(PD_REL16); }
pd_call32: { PD_BEGIN; PD_STACK(s, -4, 4, 1); SP_ADD(-4); fs32(s, EIP_OF(PD_NEXTIP)); PD_JUMP(PD_REL32); }
pd_ret16: { PD_BEGIN; PD_STACK(s, 0, 2, 0); SP_ADD(2); PD_JUMP((const u8 *) (ipd + (uword) fm16(s))); }
pd_ret32: { PD_BEGIN; PD_STACK(s, 0, 4, 0); SP_ADD(4); PD_JUMP((const u8 *) (ipd + (uword) fm32(s))); }
pd_reti16: { PD_BEGIN; PD_STACK(s, 0, 2, 0); SP_ADD(2 + (u16) pu->i); PD_JUMP((const u8 *) (ipd + (uword) fm16(s))); }
pd_reti32: { PD_BEGIN; PD_STACK(s, 0, 4, 0); SP_ADD(4 + (u16) pu->i); PD_JUMP((const u8 *) (ipd + (uword) fm32(s))); }
pd_jmpi_rw: { PD_BEGIN; PD_JUMP((const u8 *) (ipd + (uword) lreg16(pu->rm))); }
pd_jmpi_rd: { PD_BEGIN; PD_JUMP((const u8 *) (ipd + (uword) lreg32(pu->rm))); }
pd_jmpi_mw: { PD_BEGIN; PD_MEM(p, 2, 0); PD_JUMP((const u8 *) (ipd + (uword) fm16(p))); }
pd_jmpi_md: { PD_BEGIN; PD_MEM(p, 4, 0); PD_JUMP((const u8 *) (ipd + (uword) fm32(p))); }
pd_calli_rw: { PD_BEGIN; uword _v = lreg16(pu->rm); PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, EIP_OF(PD_NEXTIP)); PD_JUMP((const u8 *) (ipd + _v)); }
pd_calli_rd: { PD_BEGIN; uword _v = lreg32(pu->rm); PD_STACK(s, -4, 4, 1); SP_ADD(-4); fs32(s, EIP_OF(PD_NEXTIP)); PD_JUMP((const u8 *) (ipd + _v)); }
pd_calli_mw: { PD_BEGIN; PD_MEM(p, 2, 0); uword _v = fm16(p); PD_STACK(s, -2, 2, 1); SP_ADD(-2); fs16(s, EIP_OF(PD_NEXTIP)); PD_JUMP((const u8 *) (ipd + _v)); }
pd_calli_md: { PD_BEGIN; PD_MEM(p, 4, 0); uword _v = fm32(p); PD_STACK(s, -4, 4, 1); SP_ADD(-4); fs32(s, EIP_OF(PD_NEXTIP)); PD_JUMP((const u8 *) (ipd + _v)); }

	// ---- between blocks
pd_end: { pc = bh + pu->ip; lk = &((struct pd_uop *) pu)->link; goto pd_go; }
pd_leave: { static struct pd_block *none; none = NULL; pc = bh + pu->ip; lk = &none; goto pd_go; }   // after pd_wrote cut the block
pd_classic:   // unknown instruction, by fast_ops.h; with steps = 0 its NEXT exits to out, which returns here
	pc = bh + pu->ip;
	if (pu->rm) pd_ep++;   // may write code
	if (pu->r) DISPATCH;   // STI, MOV SS, POP SS: fast_ops.h up to its next jump
	lk = &((struct pd_uop *) pu)->link;
	pd_saved = steps;
	steps = 0;
	pd_call = true;
	DISPATCH;
pd_go:   // pc: next instruction; lk: the link slot of the uop that came here
	if (unlikely(steps < 0)) goto out;   /* first: refill runs blocks without a check (pages jumping to each other) */
	if (unlikely((uintptr_t) pc - (uintptr_t) win_lo >= (uintptr_t) win_end - (uintptr_t) win_lo)) goto refill;
	bk = *lk;
	if (likely(bk && bk->host == pc && bk->code16 == code16 && (uintptr_t) (pc + bk->span) < (uintptr_t) win_end))
		goto pd_run;
	{
		const unsigned g = pd_gen;
		bk = pd_get(cpu, pc, win_end, code16);
		if (bk && bk->n && pd_gen == g) *lk = bk;   // (not if all blocks went: lk was in one)
	}
	goto pd_try;
pd_jumped:   // from fast_ops.h, after a jump to pc
	FV_END(EIP_OF(pc));
	if (unlikely(--steps < 0)) goto out;
	if (unlikely((uintptr_t) pc - (uintptr_t) win_lo >= (uintptr_t) win_end - (uintptr_t) win_lo)) goto refill;
pd_enter:   // pc in the code window: run blocks from there
	pd_ep++;   // fast_ops.h may have written code
	bk = pd_get(cpu, pc, win_end, code16);
pd_try:   // bk from pd_get: checked
	if (unlikely(!bk || !bk->n)) DISPATCH;
	bk->ep = pd_ep;
	bk->dhi = 0;
	goto pd_start;
pd_run:   // bk from a link
	if (bk->ep != pd_ep) {   // may have been written since checked
		if (bk->dhi && bk->dep == pd_ep && pd_patch(cpu, bk)) {   // only by uops: patch in place
			bk->ep = pd_ep;
			goto pd_start;
		}
		bk->dhi = 0;
		if (unlikely(!pd_same(bk))) {
			bk = pd_get(cpu, pc, win_end, code16);
			goto pd_try;
		}
		bk->ep = pd_ep;
	}
pd_start:
	pd_cur = bk;
	bh = bk->host;
	pu = bk->u;
	goto *pu->h;
pd_slow:   // the uop's instruction to tiny386
	ins = bh + pu->ip;
	goto slow;

#undef PD_BEGIN
#undef PD_NEXTIP
#undef PD_NEXT
#undef PD_JUMP
#undef PD_EA
#undef PD_PTR
#undef PD_MEM
#undef PD_STACK
