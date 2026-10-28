/*
 * Instruction handlers, included three times in fast_exec (fast.h): _g reads operand/address sizes from the
 * prefixes; _32 and _16 have them fixed (a 66/67 prefix there continues in _g). Labels are FL(name).
 */
	// ---- prefixes
#define PFX_NEXT goto *FL(ops)[*pc++]
#define SEG_PREFIX(s) pfx = (pfx & 0x0f) | (((s) + 1) << 4); PFX_NEXT;
FL(pfx_es): SEG_PREFIX(SEG_ES)
FL(pfx_cs): SEG_PREFIX(SEG_CS)
FL(pfx_ss): SEG_PREFIX(SEG_SS)
FL(pfx_ds): SEG_PREFIX(SEG_DS)
FL(pfx_fs): SEG_PREFIX(SEG_FS)
FL(pfx_gs): SEG_PREFIX(SEG_GS)
	// sizes change: continue in the generic copy
FL(pfx_opsz): pfx = (pfx & ~1u) | ((PFX0 & 1) ^ 1); goto *ops_g[*pc++];
FL(pfx_adsz): pfx = (pfx & ~2u) | ((PFX0 & 2) ^ 2); goto *ops_g[*pc++];
FL(pfx_rep): pfx = (pfx & ~0xcu) | (1 << 2); PFX_NEXT;
FL(pfx_repne): pfx = (pfx & ~0xcu) | (2 << 2); PFX_NEXT;
FL(pfx_lock): PFX_NEXT;
FL(op_0f): goto *FL(ops0f)[*pc++];

	// ---- ALU: op Eb,Gb / Ev,Gv / Gb,Eb / Gv,Ev / AL,Ib / eAX,Iv
#define ALU6(L0, L1, L2, L3, L4, L5, OP, OPb, OPw, OPd, WR) \
L0: { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7; \
	if (m >= 0xc0) { OPb(rm, r, fr8, fw8, fr8, fw8) } \
	else { u8 *p; EA_PTR(p, m, 1, WR); OPb(p, r, fm8, fs8, fr8, fw8) } \
	NEXT; } \
L1: { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7; \
	if (m >= 0xc0) { \
		if (opsz16) { OPw(rm, r, lreg16, sreg16, lreg16, sreg16) } \
		else { OPd(rm, r, lreg32, sreg32, lreg32, sreg32) } \
	} else if (opsz16) { u8 *p; EA_PTR(p, m, 2, WR); OPw(p, r, fm16, fs16, lreg16, sreg16) } \
	else { u8 *p; EA_PTR(p, m, 4, WR); OPd(p, r, fm32, fs32, lreg32, sreg32) } \
	NEXT; } \
L2: { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7; \
	if (m >= 0xc0) { OPb(r, rm, fr8, fw8, fr8, fw8) } \
	else { u8 *p; EA_PTR(p, m, 1, 0); OPb(r, p, fr8, fw8, fm8, fs8) } \
	NEXT; } \
L3: { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7; \
	if (m >= 0xc0) { \
		if (opsz16) { OPw(r, rm, lreg16, sreg16, lreg16, sreg16) } \
		else { OPd(r, rm, lreg32, sreg32, lreg32, sreg32) } \
	} else if (opsz16) { u8 *p; EA_PTR(p, m, 2, 0); OPw(r, p, lreg16, sreg16, fm16, fs16) } \
	else { u8 *p; EA_PTR(p, m, 4, 0); OPd(r, p, lreg32, sreg32, fm32, fs32) } \
	NEXT; } \
L4: { u8 i = *pc++; int r = 0; OPb(r, i, fr8, fw8, limm, 0) NEXT; } \
L5: { int r = 0; \
	if (opsz16) { u16 i = *(u16a *) pc; pc += 2; OPw(r, i, lreg16, sreg16, limm, 0) } \
	else { u32 i = *(u32a *) pc; pc += 4; OPd(r, i, lreg32, sreg32, limm, 0) } \
	NEXT; }

	ALU6(FL(op_00), FL(op_01), FL(op_02), FL(op_03), FL(op_04), FL(op_05), ADD, ADDb, ADDw, ADDd, 1)
	ALU6(FL(op_08), FL(op_09), FL(op_0a), FL(op_0b), FL(op_0c), FL(op_0d), OR, ORb, ORw, ORd, 1)
	ALU6(FL(op_10), FL(op_11), FL(op_12), FL(op_13), FL(op_14), FL(op_15), ADC, ADCb, ADCw, ADCd, 1)
	ALU6(FL(op_18), FL(op_19), FL(op_1a), FL(op_1b), FL(op_1c), FL(op_1d), SBB, SBBb, SBBw, SBBd, 1)
	ALU6(FL(op_20), FL(op_21), FL(op_22), FL(op_23), FL(op_24), FL(op_25), AND, ANDb, ANDw, ANDd, 1)
	ALU6(FL(op_28), FL(op_29), FL(op_2a), FL(op_2b), FL(op_2c), FL(op_2d), SUB, SUBb, SUBw, SUBd, 1)
	ALU6(FL(op_30), FL(op_31), FL(op_32), FL(op_33), FL(op_34), FL(op_35), XOR, XORb, XORw, XORd, 1)
	ALU6(FL(op_38), FL(op_39), FL(op_3a), FL(op_3b), FL(op_3c), FL(op_3d), CMP, FCMPb, FCMPw, FCMPd, 0)

	// TEST, XCHG, MOV with modrm
FL(op_84): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) { FTESTb(rm, r, fr8, fw8, fr8, fw8) }
	else { u8 *p; EA_PTR(p, m, 1, 0); FTESTb(p, r, fm8, fs8, fr8, fw8) }
	NEXT; }
FL(op_85): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { FTESTw(rm, r, lreg16, sreg16, lreg16, sreg16) }
		else { FTESTd(rm, r, lreg32, sreg32, lreg32, sreg32) }
	} else if (opsz16) { u8 *p; EA_PTR(p, m, 2, 0); FTESTw(p, r, fm16, fs16, lreg16, sreg16) }
	else { u8 *p; EA_PTR(p, m, 4, 0); FTESTd(p, r, fm32, fs32, lreg32, sreg32) }
	NEXT; }
FL(op_86): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) { XCHGb(rm, r, fr8, fw8, fr8, fw8) }
	else { u8 *p; EA_PTR(p, m, 1, 1); XCHGb(p, r, fm8, fs8, fr8, fw8) }
	NEXT; }
FL(op_87): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { XCHGw(rm, r, lreg16, sreg16, lreg16, sreg16) }
		else { XCHGd(rm, r, lreg32, sreg32, lreg32, sreg32) }
	} else if (opsz16) { u8 *p; EA_PTR(p, m, 2, 1); XCHGw(p, r, fm16, fs16, lreg16, sreg16) }
	else { u8 *p; EA_PTR(p, m, 4, 1); XCHGd(p, r, fm32, fs32, lreg32, sreg32) }
	NEXT; }
FL(op_88): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) fw8(rm, fr8(r));
	else { EA_OFF(off, m) mval = fr8(r); u8 *p; FPTR_IO(p, seg, off, 1, 1, mmio_st); fs8(p, mval); }
	NEXT; }
FL(op_89): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) sreg16(rm, lreg16(r));
		else sreg32(rm, lreg32(r));
	} else if (opsz16) { EA_OFF(off, m) mval = lreg16(r); u8 *p; FPTR_IO(p, seg, off, 2, 1, mmio_st); fs16(p, mval); }
	else { EA_OFF(off, m) mval = lreg32(r); u8 *p; FPTR_IO(p, seg, off, 4, 1, mmio_st); fs32(p, mval); }
	NEXT; }
FL(op_8a): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) fw8(r, fr8(rm));
	else { EA_OFF(off, m) mreg = r; u8 *p; FPTR_IO(p, seg, off, 1, 0, mmio_ld); fw8(r, fm8(p)); }
	NEXT; }
FL(op_8b): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) sreg16(r, lreg16(rm));
		else sreg32(r, lreg32(rm));
	} else if (opsz16) { EA_OFF(off, m) mreg = r; u8 *p; FPTR_IO(p, seg, off, 2, 0, mmio_ld); sreg16(r, fm16(p)); }
	else { EA_OFF(off, m) mreg = r; u8 *p; FPTR_IO(p, seg, off, 4, 0, mmio_ld); sreg32(r, fm32(p)); }
	NEXT; }
FL(op_8c): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;   // MOV Ew,Sw
	if (r > 5) goto slow;
	if (m >= 0xc0) {
		if (opsz16) sreg16(rm, cpu->seg[r].sel);
		else sreg32(rm, cpu->seg[r].sel);
	} else { u8 *p; EA_PTR(p, m, 2, 1); fs16(p, cpu->seg[r].sel); }
	NEXT; }
FL(op_8d): { u8 m = *pc++; int r = (m >> 3) & 7;   // LEA
	if (m >= 0xc0) goto slow;
	uword a = fast_ea(cpu, &pc, m, adsz16, &seg);   // (seg is unused)
	if (opsz16) sreg16(r, a);
	else sreg32(r, a);
	NEXT; }
FL(op_8e): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;   // MOV Sw,Ew (protected mode: DS ES FS GS)
	if (r == SEG_CS || r > 5 || (PROTECTED && r == SEG_SS)) goto slow;
	u16 sel;
	if (m >= 0xc0) sel = lreg16(rm);
	else { u8 *p; EA_PTR(p, m, 2, 0); sel = fm16(p); }
	if (PROTECTED) {
		if (!FAST_LOAD_SEG(r, sel)) goto slow;
		NEXT;
	}
	cpu->seg[r].sel = sel;
	cpu->seg[r].base = sel << 4;
	cpu->seg[r].limit = 0xffff;
	cpu->seg[r].flags = 0;
	if (r == SEG_SS) {
		sp_mask = cpu->sp_mask = 0xffff;
		steps++;   // no interrupt before the next instruction
		FV_SKIP;
	}
	NEXT; }
FL(op_8f): { u8 m = *pc++; int rm = m & 7;   // POP Ev
	if (m < 0xc0) {   // address computed with SP already moved (as tiny386)
		if (((m >> 3) & 7) != 0) goto slow;
		uword sp0 = REGi(4);
		u8 *s, *p;
		if (opsz16) {
			STACK_PTR(s, 0, 2, 0); u16 v = fm16(s);
			SP_ADD(2); EA_OFF(off, m) set_sp(sp0, sp_mask);
			FPTR(p, seg, off, 2, 1); fs16(p, v); SP_ADD(2);
		} else {
			STACK_PTR(s, 0, 4, 0); u32 v = fm32(s);
			SP_ADD(4); EA_OFF(off, m) set_sp(sp0, sp_mask);
			FPTR(p, seg, off, 4, 1); fs32(p, v); SP_ADD(4);
		}
		NEXT;
	}
	if (opsz16) { u8 *s; STACK_PTR(s, 0, 2, 0); u16 v = fm16(s); SP_ADD(2); sreg16(rm, v); }
	else { u8 *s; STACK_PTR(s, 0, 4, 0); u32 v = fm32(s); SP_ADD(4); sreg32(rm, v); }
	NEXT; }

	// MOV r,imm; MOV E,imm; MOV with a direct offset
FL(op_mov_rb): { int r = pc[-1] & 7; fw8(r, *pc++); NEXT; }
FL(op_mov_rv): { int r = pc[-1] & 7;
	if (opsz16) { sreg16(r, *(u16a *) pc); pc += 2; }
	else { sreg32(r, *(u32a *) pc); pc += 4; }
	NEXT; }
FL(op_c6): { u8 m = *pc++; int rm = m & 7;
	if (((m >> 3) & 7) != 0) goto slow;
	if (m >= 0xc0) fw8(rm, *pc++);
	else { EA_OFF(off, m) mval = *pc++; u8 *p; FPTR_IO(p, seg, off, 1, 1, mmio_st); fs8(p, mval); }
	NEXT; }
FL(op_c7): { u8 m = *pc++; int rm = m & 7;
	if (((m >> 3) & 7) != 0) goto slow;
	if (m >= 0xc0) {
		if (opsz16) { sreg16(rm, *(u16a *) pc); pc += 2; }
		else { sreg32(rm, *(u32a *) pc); pc += 4; }
	} else if (opsz16) { EA_OFF(off, m) mval = *(u16a *) pc; pc += 2; u8 *p; FPTR_IO(p, seg, off, 2, 1, mmio_st); fs16(p, mval); }
	else { EA_OFF(off, m) mval = *(u32a *) pc; pc += 4; u8 *p; FPTR_IO(p, seg, off, 4, 1, mmio_st); fs32(p, mval); }
	NEXT; }
#define MOFFS(off) \
	uword off; \
	if (adsz16) { off = *(u16a *) pc; pc += 2; } else { off = *(u32a *) pc; pc += 4; } \
	seg = SEG_OVERRIDE < 0 ? SEG_DS : SEG_OVERRIDE;
FL(op_a0): { MOFFS(off) mreg = 0; u8 *p; FPTR_IO(p, seg, off, 1, 0, mmio_ld); fw8(0, fm8(p)); NEXT; }
FL(op_a1): { MOFFS(off) mreg = 0;
	if (opsz16) { u8 *p; FPTR_IO(p, seg, off, 2, 0, mmio_ld); sreg16(0, fm16(p)); }
	else { u8 *p; FPTR_IO(p, seg, off, 4, 0, mmio_ld); sreg32(0, fm32(p)); }
	NEXT; }
FL(op_a2): { MOFFS(off) mval = fr8(0); u8 *p; FPTR_IO(p, seg, off, 1, 1, mmio_st); fs8(p, mval); NEXT; }
FL(op_a3): { MOFFS(off)
	if (opsz16) { mval = lreg16(0); u8 *p; FPTR_IO(p, seg, off, 2, 1, mmio_st); fs16(p, mval); }
	else { mval = lreg32(0); u8 *p; FPTR_IO(p, seg, off, 4, 1, mmio_st); fs32(p, mval); }
	NEXT; }
FL(op_a8): { u8 i = *pc++; int r = 0; FTESTb(r, i, fr8, fw8, limm, 0) NEXT; }
FL(op_a9): { int r = 0;
	if (opsz16) { u16 i = *(u16a *) pc; pc += 2; FTESTw(r, i, lreg16, sreg16, limm, 0) }
	else { u32 i = *(u32a *) pc; pc += 4; FTESTd(r, i, lreg32, sreg32, limm, 0) }
	NEXT; }

	// INC, DEC, PUSH, POP of registers
FL(op_inc_r): { int r = pc[-1] & 7;
	if (opsz16) { INCw(r, lreg16, sreg16) } else { INCd(r, lreg32, sreg32) }
	NEXT; }
FL(op_dec_r): { int r = pc[-1] & 7;
	if (opsz16) { DECw(r, lreg16, sreg16) } else { DECd(r, lreg32, sreg32) }
	NEXT; }
FL(op_push_r): { int r = pc[-1] & 7;
	if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); u16 v = lreg16(r); SP_ADD(-2); fs16(s, v); }
	else { u8 *s; STACK_PTR(s, -4, 4, 1); u32 v = lreg32(r); SP_ADD(-4); fs32(s, v); }
	NEXT; }
FL(op_pop_r): { int r = pc[-1] & 7;
	if (opsz16) { u8 *s; STACK_PTR(s, 0, 2, 0); u16 v = fm16(s); SP_ADD(2); sreg16(r, v); }
	else { u8 *s; STACK_PTR(s, 0, 4, 0); u32 v = fm32(s); SP_ADD(4); sreg32(r, v); }
	NEXT; }
FL(op_push_iv): {
	if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); SP_ADD(-2); fs16(s, *(u16a *) pc); pc += 2; }
	else { u8 *s; STACK_PTR(s, -4, 4, 1); SP_ADD(-4); fs32(s, *(u32a *) pc); pc += 4; }
	NEXT; }
FL(op_push_ib): { uword v = (sword) (s8) *pc++;
	if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); SP_ADD(-2); fs16(s, v); }
	else { u8 *s; STACK_PTR(s, -4, 4, 1); SP_ADD(-4); fs32(s, v); }
	NEXT; }
FL(op_pusha): {
	if (opsz16) {
		u8 *s; STACK_PTR(s, -16, 16, 1);
		uword sp = REGi(4);
		for (int i = 0; i < 8; i++)
			fs16(s + 14 - 2 * i, i == 4 ? sp : lreg16(i));
		SP_ADD(-16);
	} else {
		u8 *s; STACK_PTR(s, -32, 32, 1);
		uword sp = REGi(4);
		for (int i = 0; i < 8; i++)
			fs32(s + 28 - 4 * i, i == 4 ? sp : lreg32(i));
		SP_ADD(-32);
	}
	NEXT; }
FL(op_popa): {
	if (opsz16) {
		u8 *s; STACK_PTR(s, 0, 16, 0);
		for (int i = 0; i < 8; i++)
			if (i != 4) sreg16(i, fm16(s + 14 - 2 * i));
		SP_ADD(16);
	} else {
		u8 *s; STACK_PTR(s, 0, 32, 0);
		for (int i = 0; i < 8; i++)
			if (i != 4) sreg32(i, fm32(s + 28 - 4 * i));
		SP_ADD(32);
	}
	NEXT; }

	// ARPL, protected mode only; memory written only if RPL goes up (as tiny386)
FL(op_arpl): { if (!PROTECTED) goto slow;
	u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	u16 src = lreg16(r);
	if (m >= 0xc0) {
		u16 dst = lreg16(rm);
		if ((dst & 3) < (src & 3)) { cpu->flags |= ZF; sreg16(rm, (dst & ~3) | (src & 3)); }
		else cpu->flags &= ~ZF;
	} else {
		EA_OFF(off, m) u8 *p; FPTR(p, seg, off, 2, 0);
		u16 dst = fm16(p);
		if ((dst & 3) < (src & 3)) { FPTR(p, seg, off, 2, 1); cpu->flags |= ZF; fs16(p, (dst & ~3) | (src & 3)); }
		else cpu->flags &= ~ZF;
	}
	cpu->cc.mask &= ~ZF;
	NEXT; }

	// segment registers; protected-mode loads by set_seg (a fault: tiny386 redoes the instruction)
FL(op_push_seg): {
	u8 op = pc[-1];   // 06 0E 16 1E, 0F A0, 0F A8
	int sg = op == 0xa0 ? SEG_FS : op == 0xa8 ? SEG_GS : op >> 3;
	if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); SP_ADD(-2); fs16(s, cpu->seg[sg].sel); }
	else { u8 *s; STACK_PTR(s, -4, 2, 1); SP_ADD(-4); fs16(s, cpu->seg[sg].sel); }
	NEXT; }
FL(op_pop_seg): {
	u8 op = pc[-1];
	int sg = op == 0xa1 ? SEG_FS : op == 0xa9 ? SEG_GS : op >> 3;   // 07 17 1F, 0F A1, 0F A9
	if (PROTECTED && sg == SEG_SS) goto slow;
	u8 *s; STACK_PTR(s, 0, 2, 0);
	u16 sel = fm16(s);
	if (PROTECTED) {
		if (!FAST_LOAD_SEG(sg, sel)) goto slow;
		SP_ADD(opsz16 ? 2 : 4);
		NEXT;
	}
	SP_ADD(opsz16 ? 2 : 4);
	cpu->seg[sg].sel = sel;
	cpu->seg[sg].base = sel << 4;
	cpu->seg[sg].limit = 0xffff;
	cpu->seg[sg].flags = 0;
	if (sg == SEG_SS) {
		sp_mask = cpu->sp_mask = 0xffff;
		steps++;
		FV_SKIP;
	}
	NEXT; }
FL(op_les): FL(op_lds): { u8 m = *pc++; int r = (m >> 3) & 7;
	if (m >= 0xc0) goto slow;
	int sg = pc[-2] == 0xc4 ? SEG_ES : SEG_DS;
	u8 *p;
	if (PROTECTED) {   // selector first (as tiny386): a fault leaves the register as it was
		u32 off;
		u16 sel;
		if (opsz16) { EA_PTR(p, m, 4, 0); off = fm16(p); sel = fm16(p + 2); }
		else { EA_PTR(p, m, 6, 0); off = fm32(p); sel = fm16(p + 4); }
		if (!FAST_LOAD_SEG(sg, sel)) goto slow;
		if (opsz16) sreg16(r, off); else sreg32(r, off);
		NEXT;
	}
	if (opsz16) {
		EA_PTR(p, m, 4, 0);
		sreg16(r, fm16(p));
		u16 sel = fm16(p + 2);
		cpu->seg[sg].sel = sel;
		cpu->seg[sg].base = sel << 4;
	} else {
		EA_PTR(p, m, 6, 0);
		sreg32(r, fm32(p));
		u16 sel = fm16(p + 4);
		cpu->seg[sg].sel = sel;
		cpu->seg[sg].base = sel << 4;
	}
	cpu->seg[sg].limit = 0xffff;
	cpu->seg[sg].flags = 0;
	NEXT; }

	// IMUL with an immediate, PUSHF/POPF, flags
FL(op_imul_iv): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (opsz16) {
		if (m >= 0xc0) { u16 i = *(u16a *) pc; pc += 2; IMUL2wIw(r, rm, i, lreg16, sreg16, lreg16, sreg16) }
		else { u8 *p; EA_PTR(p, m, 2, 0); u16 i = *(u16a *) pc; pc += 2; IMUL2wIw(r, p, i, lreg16, sreg16, fm16, fs16) }
	} else {
		if (m >= 0xc0) { u32 i = *(u32a *) pc; pc += 4; IMUL2dId(r, rm, i, lreg32, sreg32, lreg32, sreg32) }
		else { u8 *p; EA_PTR(p, m, 4, 0); u32 i = *(u32a *) pc; pc += 4; IMUL2dId(r, p, i, lreg32, sreg32, fm32, fs32) }
	}
	NEXT; }
FL(op_imul_ib): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (opsz16) {
		if (m >= 0xc0) { u8 i = *pc++; IMUL2wIb(r, rm, i, lreg16, sreg16, lreg16, sreg16) }
		else { u8 *p; EA_PTR(p, m, 2, 0); u8 i = *pc++; IMUL2wIb(r, p, i, lreg16, sreg16, fm16, fs16) }
	} else {
		if (m >= 0xc0) { u8 i = *pc++; IMUL2dIb(r, rm, i, lreg32, sreg32, lreg32, sreg32) }
		else { u8 *p; EA_PTR(p, m, 4, 0); u8 i = *pc++; IMUL2dIb(r, p, i, lreg32, sreg32, fm32, fs32) }
	}
	NEXT; }
FL(op_pushf): {
	if (!V86_IOPL3) goto slow;
	if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); refresh_flags(cpu); cpu->cc.mask = 0; SP_ADD(-2); fs16(s, cpu->flags); }
	else { u8 *s; STACK_PTR(s, -4, 4, 1); refresh_flags(cpu); cpu->cc.mask = 0; SP_ADD(-4); fs32(s, cpu->flags & ~(RF | VM)); }
	NEXT; }
FL(op_popf): {
	if (!V86_IOPL3) goto slow;
	uword mask = VM;
	if (PMODE) {
		if (cpu->cpl > 0) mask |= IOPL;
		if (get_IOPL(cpu) < cpu->cpl) mask |= IF;
	}
	if (opsz16) {
		u8 *s; STACK_PTR(s, 0, 2, 0);
		SP_ADD(2);
		cpu->flags = (cpu->flags & (0xffff0000 | mask)) | (fm16(s) & ~mask);
	} else {
		u8 *s; STACK_PTR(s, 0, 4, 0);
		SP_ADD(4);
		cpu->flags = (cpu->flags & mask) | (fm32(s) & ~mask);
	}
	cpu->flags &= EFLAGS_MASK;
	cpu->flags |= 0x2;
	cpu->cc.mask = 0;
	if (cpu->intr && (cpu->flags & IF)) {   // take the interrupt now, as tiny386
		FV_END(EIP_OF(pc));
		goto out;
	}
	NEXT; }
FL(op_sahf): { SAHF() NEXT; }
FL(op_lahf): { LAHF() NEXT; }
FL(op_cmc): { CMC() NEXT; }
FL(op_clc): { CLC() NEXT; }
FL(op_stc): { STC() NEXT; }
FL(op_cld): { CLD() NEXT; }
FL(op_std): { STD() NEXT; }
FL(op_cli): {
	if (get_IOPL(cpu) < cpu->cpl) goto slow;
	cpu->flags &= ~IF;
	NEXT; }
FL(op_sti): {
	if (get_IOPL(cpu) < cpu->cpl) goto slow;
	FV_SKIP;   // (tiny386 runs the next instruction with it)
	cpu->flags |= IF;
	if (cpu->intr || steps < 1) steps = 1;   // interrupts after the next instruction
	NEXT; }
FL(op_nop): NEXT;
FL(op_xchg_ax): { int r = pc[-1] & 7;
	if (opsz16) { u16 t = lreg16(r); sreg16(r, lreg16(0)); sreg16(0, t); }
	else { u32 t = lreg32(r); sreg32(r, lreg32(0)); sreg32(0, t); }
	NEXT; }
FL(op_cbw): { CBW_CWDE() NEXT; }
FL(op_cwd): { CWD_CDQ() NEXT; }
FL(op_xlat): {
	seg = SEG_OVERRIDE < 0 ? SEG_DS : SEG_OVERRIDE;
	uword off = adsz16 ? (uword) ((lreg16(3) + fr8(0)) & 0xffff) : lreg32(3) + fr8(0);
	u8 *p; FPTR(p, seg, off, 1, 0);
	fw8(0, fm8(p));
	NEXT; }

	// jumps, calls, returns, loops
FL(op_jcc_b): { s8 d = *pc++;
	if (fast_cond(cpu, pc[-2] & 15)) JUMP_REL(d);
	NEXT; }
FL(op_jcc_v): {   // rel16/32 by operand size
	int c = pc[-1] & 15;
	sword d;
	if (opsz16) { d = (s16) *(u16a *) pc; pc += 2; } else { d = (s32) *(u32a *) pc; pc += 4; }
	if (fast_cond(cpu, c)) JUMP_REL(d);
	NEXT; }
FL(op_setcc): { u8 m = *pc++; int rm = m & 7;
	int c = fast_cond(cpu, pc[-2] & 15);
	if (m >= 0xc0) fw8(rm, c);
	else { u8 *p; EA_PTR(p, m, 1, 1); fs8(p, c); }
	NEXT; }
FL(op_jmp_b): { s8 d = *pc++; JUMP_REL(d); NEXT; }
FL(op_jmp_v): {
	sword d;
	if (opsz16) { d = (s16) *(u16a *) pc; pc += 2; } else { d = (s32) *(u32a *) pc; pc += 4; }
	JUMP_REL(d);
	NEXT; }
FL(op_call): {
	sword d;
	if (opsz16) {
		d = (s16) *(u16a *) pc; pc += 2;
		u8 *s; STACK_PTR(s, -2, 2, 1);
		SP_ADD(-2); fs16(s, EIP_OF(pc));
	} else {
		d = (s32) *(u32a *) pc; pc += 4;
		u8 *s; STACK_PTR(s, -4, 4, 1);
		SP_ADD(-4); fs32(s, EIP_OF(pc));
	}
	JUMP_REL(d);
	NEXT; }
FL(op_ret): {
	if (opsz16) { u8 *s; STACK_PTR(s, 0, 2, 0); SP_ADD(2); JUMP_ABS(fm16(s)); }
	else { u8 *s; STACK_PTR(s, 0, 4, 0); SP_ADD(4); JUMP_ABS(fm32(s)); }
	NEXT; }
FL(op_ret_iw): { u16 n = *(u16a *) pc; pc += 2;
	if (opsz16) { u8 *s; STACK_PTR(s, 0, 2, 0); SP_ADD(2 + n); JUMP_ABS(fm16(s)); }
	else { u8 *s; STACK_PTR(s, 0, 4, 0); SP_ADD(4 + n); JUMP_ABS(fm32(s)); }
	NEXT; }
FL(op_loop): { s8 d = *pc++;
	if (adsz16) { u16 c = lreg16(1) - 1; sreg16(1, c); if (c) JUMP_REL(d); }
	else { u32 c = lreg32(1) - 1; sreg32(1, c); if (c) JUMP_REL(d); }
	NEXT; }
FL(op_loope): { s8 d = *pc++;
	if (adsz16) { u16 c = lreg16(1) - 1; sreg16(1, c); if (c && get_ZF(cpu)) JUMP_REL(d); }
	else { u32 c = lreg32(1) - 1; sreg32(1, c); if (c && get_ZF(cpu)) JUMP_REL(d); }
	NEXT; }
FL(op_loopne): { s8 d = *pc++;
	if (adsz16) { u16 c = lreg16(1) - 1; sreg16(1, c); if (c && !get_ZF(cpu)) JUMP_REL(d); }
	else { u32 c = lreg32(1) - 1; sreg32(1, c); if (c && !get_ZF(cpu)) JUMP_REL(d); }
	NEXT; }
FL(op_jcxz): { s8 d = *pc++;
	if (adsz16 ? lreg16(1) == 0 : lreg32(1) == 0) JUMP_REL(d);
	NEXT; }
FL(op_enter): {   // nesting level 0 only
	u16 size = *(u16a *) pc;
	if (pc[2] & 31) goto slow;
	pc += 3;
	if (opsz16) {
		u8 *s; STACK_PTR(s, -2, 2, 1);
		uword sp = REGi(4);
		set_sp(sp - 2 - size, sp_mask);
		fs16(s, lreg16(5));
		sreg16(5, (sp - 2) & sp_mask);
	} else {
		u8 *s; STACK_PTR(s, -4, 4, 1);
		uword sp = REGi(4);
		set_sp(sp - 4 - size, sp_mask);
		fs32(s, lreg32(5));
		sreg32(5, (sp - 4) & sp_mask);
	}
	NEXT; }
FL(op_leave): {
	uword bp = REGi(5) & sp_mask;
	if (opsz16) {
		u8 *p; FPTR(p, SEG_SS, bp, 2, 0);
		set_sp(REGi(5) + 2, sp_mask);
		sreg16(5, fm16(p));
	} else {
		u8 *p; FPTR(p, SEG_SS, bp, 4, 0);
		set_sp(REGi(5) + 4, sp_mask);
		sreg32(5, fm32(p));
	}
	NEXT; }

	// far jumps, calls, returns, INT, IRET: real mode here, protected mode by pmcall/pmret or tiny386
#define LOAD_CS(sel) do { \
		cpu->seg[SEG_CS].sel = (sel); \
		cpu->seg[SEG_CS].base = (uword) (sel) << 4; \
		cpu->seg[SEG_CS].limit = 0xffff; \
		cpu->seg[SEG_CS].flags = 0; \
		cpu->cpl = cpu->flags & VM ? 3 : 0; \
		cpu->code16 = true; \
	} while (0)
FL(op_jmpf): {
	uword off;
	if (opsz16) { off = *(u16a *) pc; pc += 2; } else { off = *(u32a *) pc; pc += 4; }
	u16 sel = *(u16a *) pc;
	if (PROTECTED) { pc += 2; PM_FAR(pmcall(cpu, opsz16, off, sel, true)); }
	LOAD_CS(sel);
	eip = off;
	RELOAD; }
FL(op_callf): {
	uword off;
	if (opsz16) { off = *(u16a *) pc; pc += 2; } else { off = *(u32a *) pc; pc += 4; }
	u16 sel = *(u16a *) pc; pc += 2;
	if (PROTECTED) PM_FAR(pmcall(cpu, opsz16, off, sel, false));
	if (opsz16) {
		u8 *s; STACK_PTR(s, -4, 4, 1);
		SP_ADD(-4);
		fs16(s + 2, cpu->seg[SEG_CS].sel);
		fs16(s, EIP_OF(pc));
	} else {
		u8 *s; STACK_PTR(s, -8, 8, 1);
		SP_ADD(-8);
		fs32(s + 4, cpu->seg[SEG_CS].sel);
		fs32(s, EIP_OF(pc));
	}
	LOAD_CS(sel);
	eip = off;
	RELOAD; }
FL(op_retf): {
	uword n = 0;
	if (pc[-1] == 0xca) { n = *(u16a *) pc; pc += 2; }
	if (PROTECTED) PM_FAR(pmret(cpu, opsz16, n, false));
	if (opsz16) {
		u8 *s; STACK_PTR(s, 0, 4, 0);
		eip = fm16(s);
		u16 sel = fm16(s + 2);
		LOAD_CS(sel);
		SP_ADD(4 + n);
	} else {
		u8 *s; STACK_PTR(s, 0, 8, 0);
		eip = fm32(s);
		u16 sel = fm32(s + 4);
		LOAD_CS(sel);
		SP_ADD(8 + n);
	}
	RELOAD; }
FL(op_int): {   // INT n, real mode
	if (PMODE) goto slow;
	u8 n = *pc++;
	u8 *v; uword vec = cpu->idt.base + n * 4;
	if ((vec & 0xfff) > 0xffc || vec >= 0xa0000) goto slow;
	v = cpu->phys_mem + vec;
	u8 *s; STACK_PTR(s, -6, 6, 1);
	const u16 off = fm16(v), sel = fm16(v + 2);   // before the pushes: the stack may overlap the vector
	refresh_flags(cpu);
	cpu->cc.mask = 0;
	fs16(s + 4, cpu->flags);
	fs16(s + 2, cpu->seg[SEG_CS].sel);
	fs16(s, EIP_OF(pc));
	SP_ADD(-6);
	eip = off;
	LOAD_CS(sel);
	cpu->flags &= ~(IF | TF);
	RELOAD; }
FL(op_iret): {   // protected mode by pmret
	if (PROTECTED) PM_FAR(pmret(cpu, opsz16, 0, true));
	if (!opsz16 || (cpu->flags & VM)) goto slow;
	u8 *s; STACK_PTR(s, 0, 6, 0);
	eip = fm16(s);
	u16 sel = fm16(s + 2);
	cpu->flags = (cpu->flags & 0xffff0000) | fm16(s + 4);
	cpu->flags &= EFLAGS_MASK;
	cpu->flags |= 0x2;
	LOAD_CS(sel);
	cpu->cc.mask = 0;
	SP_ADD(6);
	if (cpu->intr && (cpu->flags & IF)) {   // take the interrupt now, as tiny386
		FV_END(eip);
		cpu->next_ip = eip;
		goto out_ip;
	}
	RELOAD; }

	// groups
FL(op_grp1_b): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		u8 i = *pc++;
		switch (op) {
		case 0: { ADDb(rm, i, fr8, fw8, limm, 0) } break;
		case 1: { ORb(rm, i, fr8, fw8, limm, 0) } break;
		case 2: { ADCb(rm, i, fr8, fw8, limm, 0) } break;
		case 3: { SBBb(rm, i, fr8, fw8, limm, 0) } break;
		case 4: { ANDb(rm, i, fr8, fw8, limm, 0) } break;
		case 5: { SUBb(rm, i, fr8, fw8, limm, 0) } break;
		case 6: { XORb(rm, i, fr8, fw8, limm, 0) } break;
		default: { FCMPb(rm, i, fr8, fw8, limm, 0) } break;
		}
	} else {
		u8 *p; EA_PTR(p, m, 1, op != 7);
		u8 i = *pc++;
		switch (op) {
		case 0: { ADDb(p, i, fm8, fs8, limm, 0) } break;
		case 1: { ORb(p, i, fm8, fs8, limm, 0) } break;
		case 2: { ADCb(p, i, fm8, fs8, limm, 0) } break;
		case 3: { SBBb(p, i, fm8, fs8, limm, 0) } break;
		case 4: { ANDb(p, i, fm8, fs8, limm, 0) } break;
		case 5: { SUBb(p, i, fm8, fs8, limm, 0) } break;
		case 6: { XORb(p, i, fm8, fs8, limm, 0) } break;
		default: { FCMPb(p, i, fm8, fs8, limm, 0) } break;
		}
	}
	NEXT; }
#define GRP1_V(I16, I32) \
	if (m >= 0xc0) { \
		if (opsz16) { \
			u16 i = I16; \
			switch (op) { \
			case 0: { ADDw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 1: { ORw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 2: { ADCw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 3: { SBBw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 4: { ANDw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 5: { SUBw(rm, i, lreg16, sreg16, limm, 0) } break; \
			case 6: { XORw(rm, i, lreg16, sreg16, limm, 0) } break; \
			default: { FCMPw(rm, i, lreg16, sreg16, limm, 0) } break; \
			} \
		} else { \
			u32 i = I32; \
			switch (op) { \
			case 0: { ADDd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 1: { ORd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 2: { ADCd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 3: { SBBd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 4: { ANDd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 5: { SUBd(rm, i, lreg32, sreg32, limm, 0) } break; \
			case 6: { XORd(rm, i, lreg32, sreg32, limm, 0) } break; \
			default: { FCMPd(rm, i, lreg32, sreg32, limm, 0) } break; \
			} \
		} \
	} else if (opsz16) { \
		u8 *p; EA_PTR(p, m, 2, op != 7); \
		u16 i = I16; \
		switch (op) { \
		case 0: { ADDw(p, i, fm16, fs16, limm, 0) } break; \
		case 1: { ORw(p, i, fm16, fs16, limm, 0) } break; \
		case 2: { ADCw(p, i, fm16, fs16, limm, 0) } break; \
		case 3: { SBBw(p, i, fm16, fs16, limm, 0) } break; \
		case 4: { ANDw(p, i, fm16, fs16, limm, 0) } break; \
		case 5: { SUBw(p, i, fm16, fs16, limm, 0) } break; \
		case 6: { XORw(p, i, fm16, fs16, limm, 0) } break; \
		default: { FCMPw(p, i, fm16, fs16, limm, 0) } break; \
		} \
	} else { \
		u8 *p; EA_PTR(p, m, 4, op != 7); \
		u32 i = I32; \
		switch (op) { \
		case 0: { ADDd(p, i, fm32, fs32, limm, 0) } break; \
		case 1: { ORd(p, i, fm32, fs32, limm, 0) } break; \
		case 2: { ADCd(p, i, fm32, fs32, limm, 0) } break; \
		case 3: { SBBd(p, i, fm32, fs32, limm, 0) } break; \
		case 4: { ANDd(p, i, fm32, fs32, limm, 0) } break; \
		case 5: { SUBd(p, i, fm32, fs32, limm, 0) } break; \
		case 6: { XORd(p, i, fm32, fs32, limm, 0) } break; \
		default: { FCMPd(p, i, fm32, fs32, limm, 0) } break; \
		} \
	}
FL(op_grp1_v): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	GRP1_V((pc += 2, *(u16a *) (pc - 2)), (pc += 4, *(u32a *) (pc - 4)))
	NEXT; }
FL(op_grp1_vb): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	GRP1_V((u16) (s8) *pc++, (u32) (s8) *pc++)
	NEXT; }

	// shifts and rotates: C0 (Eb,Ib) C1 (Ev,Ib) D0 (Eb,1) D1 (Ev,1) D2 (Eb,CL) D3 (Ev,CL)
#define GRP2_CASES(SFX, X, N, LA, SA) \
		switch (op) { \
		case 0: { ROL##SFX(X, N, LA, SA, limm, 0) } break; \
		case 1: { ROR##SFX(X, N, LA, SA, limm, 0) } break; \
		case 2: { RCL##SFX(X, N, LA, SA, limm, 0) } break; \
		case 3: { RCR##SFX(X, N, LA, SA, limm, 0) } break; \
		case 4: case 6: { SHL##SFX(X, N, LA, SA, limm, 0) } break; \
		case 5: { SHR##SFX(X, N, LA, SA, limm, 0) } break; \
		default: { SAR##SFX(X, N, LA, SA, limm, 0) } break; \
		}
FL(op_grp2_b): { u8 b = pc[-1]; u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		u8 n = b == 0xc0 ? *pc++ : b == 0xd0 ? 1 : fr8(1);
		GRP2_CASES(b, rm, n, fr8, fw8)
	} else {
		u8 *p; EA_PTR(p, m, 1, 1);
		u8 n = b == 0xc0 ? *pc++ : b == 0xd0 ? 1 : fr8(1);
		GRP2_CASES(b, p, n, fm8, fs8)
	}
	NEXT; }
FL(op_grp2_v): { u8 b = pc[-1]; u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		u8 n = b == 0xc1 ? *pc++ : b == 0xd1 ? 1 : fr8(1);
		if (opsz16) { GRP2_CASES(w, rm, n, lreg16, sreg16) }
		else { GRP2_CASES(d, rm, n, lreg32, sreg32) }
	} else if (opsz16) {
		u8 *p; EA_PTR(p, m, 2, 1);
		u8 n = b == 0xc1 ? *pc++ : b == 0xd1 ? 1 : fr8(1);
		GRP2_CASES(w, p, n, fm16, fs16)
	} else {
		u8 *p; EA_PTR(p, m, 4, 1);
		u8 n = b == 0xc1 ? *pc++ : b == 0xd1 ? 1 : fr8(1);
		GRP2_CASES(d, p, n, fm32, fs32)
	}
	NEXT; }

	// F6/F7: TEST NOT NEG MUL IMUL DIV IDIV
#define GRP3(SFX, SZ, X, LA, SA, IMM) \
		switch (op) { \
		case 0: case 1: { u##SZ i = IMM; FTEST##SFX(X, i, LA, SA, limm, 0) } break; \
		case 2: { NOT##SFX(X, LA, SA) } break; \
		case 3: { NEG##SFX(X, LA, SA) } break; \
		case 4: { MUL##SFX(X, LA, SA) } break; \
		case 5: { IMUL##SFX(X, LA, SA) } break; \
		case 6: { cpu->ip = EIP_OF(ins); DIV##SFX(X, LA, SA) } break;   /* #DE at the instruction */ \
		default: { cpu->ip = EIP_OF(ins); IDIV##SFX(X, LA, SA) } break; \
		}
FL(op_grp3_b): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) { GRP3(b, 8, rm, fr8, fw8, *pc++) }
	else { u8 *p; EA_PTR(p, m, 1, op == 2 || op == 3); GRP3(b, 8, p, fm8, fs8, *pc++) }
	NEXT; }
FL(op_grp3_v): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { GRP3(w, 16, rm, lreg16, sreg16, (pc += 2, *(u16a *) (pc - 2))) }
		else { GRP3(d, 32, rm, lreg32, sreg32, (pc += 4, *(u32a *) (pc - 4))) }
	} else if (opsz16) {
		u8 *p; EA_PTR(p, m, 2, op == 2 || op == 3);
		GRP3(w, 16, p, fm16, fs16, (pc += 2, *(u16a *) (pc - 2)))
	} else {
		u8 *p; EA_PTR(p, m, 4, op == 2 || op == 3);
		GRP3(d, 32, p, fm32, fs32, (pc += 4, *(u32a *) (pc - 4)))
	}
	NEXT; }

	// FE: INC/DEC Eb; FF: INC/DEC Ev, CALL/JMP Ev, far CALL/JMP Mp, PUSH Ev
FL(op_grp4): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (op > 1) goto slow;
	if (m >= 0xc0) {
		if (op == 0) { INCb(rm, fr8, fw8) } else { DECb(rm, fr8, fw8) }
	} else {
		u8 *p; EA_PTR(p, m, 1, 1);
		if (op == 0) { INCb(p, fm8, fs8) } else { DECb(p, fm8, fs8) }
	}
	NEXT; }
FL(op_grp5): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;
	if (op == 7 || ((op == 3 || op == 5) && m >= 0xc0)) goto slow;
	if (op == 3 || op == 5) {   // far CALL/JMP through memory
		u8 *p;
		uword off;
		u16 sel;
		if (opsz16) { EA_PTR(p, m, 4, 0); off = fm16(p); sel = fm16(p + 2); }
		else { EA_PTR(p, m, 6, 0); off = fm32(p); sel = fm16(p + 4); }
		if (PROTECTED) PM_FAR(pmcall(cpu, opsz16, off, sel, op == 5));
		if (op == 3) {
			if (opsz16) {
				u8 *s; STACK_PTR(s, -4, 4, 1);
				SP_ADD(-4);
				fs16(s + 2, cpu->seg[SEG_CS].sel);
				fs16(s, EIP_OF(pc));
			} else {
				u8 *s; STACK_PTR(s, -8, 8, 1);
				SP_ADD(-8);
				fs32(s + 4, cpu->seg[SEG_CS].sel);
				fs32(s, EIP_OF(pc));
			}
		}
		LOAD_CS(sel);
		eip = off;
		RELOAD;
	}
	uword v;
	u8 *p = NULL;
	if (m >= 0xc0) v = opsz16 ? lreg16(rm) : lreg32(rm);
	else if (opsz16) { EA_PTR(p, m, 2, op < 2); v = fm16(p); }
	else { EA_PTR(p, m, 4, op < 2); v = fm32(p); }
	switch (op) {
	case 0: case 1:
		if (p) {
			if (opsz16) { if (op == 0) { INCw(p, fm16, fs16) } else { DECw(p, fm16, fs16) } }
			else { if (op == 0) { INCd(p, fm32, fs32) } else { DECd(p, fm32, fs32) } }
		} else {
			if (opsz16) { if (op == 0) { INCw(rm, lreg16, sreg16) } else { DECw(rm, lreg16, sreg16) } }
			else { if (op == 0) { INCd(rm, lreg32, sreg32) } else { DECd(rm, lreg32, sreg32) } }
		}
		break;
	case 2:
		if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); SP_ADD(-2); fs16(s, EIP_OF(pc)); }
		else { u8 *s; STACK_PTR(s, -4, 4, 1); SP_ADD(-4); fs32(s, EIP_OF(pc)); }
		JUMP_ABS(v);
		break;
	case 4:
		JUMP_ABS(v);
		break;
	default:   // 6: PUSH
		if (opsz16) { u8 *s; STACK_PTR(s, -2, 2, 1); SP_ADD(-2); fs16(s, v); }
		else { u8 *s; STACK_PTR(s, -4, 4, 1); SP_ADD(-4); fs32(s, v); }
		break;
	}
	NEXT; }

	// string instructions; REP runs in chunks within a page
#define STR_SEG (SEG_OVERRIDE < 0 ? SEG_DS : SEG_OVERRIDE)
#define SI_ (adsz16 ? lreg16(6) : lreg32(6))
#define DI_ (adsz16 ? lreg16(7) : lreg32(7))
#define CX_ (adsz16 ? lreg16(1) : lreg32(1))
#define SET_SI(v) do { if (adsz16) sreg16(6, v); else sreg32(6, v); } while (0)
#define SET_DI(v) do { if (adsz16) sreg16(7, v); else sreg32(7, v); } while (0)
#define SET_CX(v) do { if (adsz16) sreg16(1, v); else sreg32(1, v); } while (0)
	// elements of n bytes left in the page from lin, in direction dir
#define IN_PAGE(lin, n, dir) ((dir) > 0 ? (0x1000 - ((lin) & 0xfff)) / (n) : ((lin) & 0xfff) / (n) + 1)
FL(op_movsb): strn = 1; goto FL(movs);
FL(op_movs): strn = opsz16 ? 2 : 4;
FL(movs): { int n = strn;
	int dir = (cpu->flags & DF) ? -n : n;
	int ss = STR_SEG;
	if (!rep) {
		u8 *s, *d;
		FPTR_IO(s, ss, SI_, n, 0, FL(movs_io));
		FPTR_IO(d, SEG_ES, DI_, n, 1, FL(movs_io));
		if (n == 1) fs8(d, fm8(s)); else if (n == 2) fs16(d, fm16(s)); else fs32(d, fm32(s));
		SET_SI(SI_ + dir);
		SET_DI(DI_ + dir);
		NEXT;
FL(movs_io):   // either side may be MMIO; both checked before any read (reads have side effects)
		{
			if (unlikely(nullsegs) && (nullsegs & ((1 << ss) | (1 << SEG_ES)))) goto slow;   // (FPTR_IO came here before ES's check)
			uword ps = 0, pd = 0;
			int ks = fast_where(cpu, cpu->seg[ss].base + SI_, n, 0, &s, &ps);
			int kd = fast_where(cpu, cpu->seg[SEG_ES].base + DI_, n, 1, &d, &pd);
			if (!ks || !kd) goto slow;
			FV_SKIP;
			u32 v = ks == 1 ? (n == 1 ? fm8(s) : n == 2 ? fm16(s) : fm32(s)) : fast_io_read(cpu, ps, n);
			if (kd == 2) fast_io_write(cpu, pd, n, v);
			else if (n == 1) fs8(d, v); else if (n == 2) fs16(d, v); else fs32(d, v);
			SET_SI(SI_ + dir);
			SET_DI(DI_ + dir);
			NEXT;
		}
	}
	while (CX_) {
		uword si = SI_, di = DI_;
		uword ls = cpu->seg[ss].base + si, ld = cpu->seg[SEG_ES].base + di;
		if ((ls | ld) & (n - 1)) goto slow;   // misaligned: tiny386
		uword cnt = CX_, c1 = IN_PAGE(ls, n, dir), c2 = IN_PAGE(ld, n, dir);
		if (c1 < cnt) cnt = c1;
		if (c2 < cnt) cnt = c2;
		if (adsz16 && (dir > 0 ? (si > di ? si : di) + cnt * n > 0x10000 : (si < di ? si : di) < (cnt - 1) * n))
			goto slow;   // would wrap around the segment: tiny386
		u8 *s, *d;
		FPTR(s, ss, si, n, 0);
		FPTR(d, SEG_ES, di, n, 1);
		if (dir > 0 && (d + cnt * n <= s || d >= s + cnt * n)) {
			FMEMCPY(d, s, cnt * n);
		} else {
			for (uword i = 0; i < cnt; i++, s += dir, d += dir) {
				if (n == 1) fs8(d, fm8(s)); else if (n == 2) fs16(d, fm16(s)); else fs32(d, fm32(s));
			}
		}
		SET_SI(si + cnt * dir);
		SET_DI(di + cnt * dir);
		SET_CX(CX_ - cnt);
	}
	NEXT; }
FL(op_stosb): strn = 1; goto FL(stos);
FL(op_stos): strn = opsz16 ? 2 : 4;
FL(stos): { int n = strn;
	int dir = (cpu->flags & DF) ? -n : n;
	u32 v = REGi(0);
	if (!rep) {
		u8 *d; FPTR_IO(d, SEG_ES, DI_, n, 1, FL(stos_io));
		if (n == 1) fs8(d, v); else if (n == 2) fs16(d, v); else fs32(d, v);
		SET_DI(DI_ + dir);
		NEXT;
FL(stos_io): {
			uword pa = fast_mmio_addr(cpu, mlin, n, 1);
			if (pa == (uword) -1) goto slow;
			FV_SKIP;
			fast_io_write(cpu, pa, n, v);
			SET_DI(DI_ + dir);
			NEXT;
		}
	}
	while (CX_) {
		uword di = DI_;
		uword ld = cpu->seg[SEG_ES].base + di;
		if (ld & (n - 1)) goto slow;
		uword cnt = CX_, c2 = IN_PAGE(ld, n, dir);
		if (c2 < cnt) cnt = c2;
		if (adsz16 && (dir > 0 ? di + cnt * n > 0x10000 : di < (cnt - 1) * n))
			goto slow;
		u8 *d; FPTR_IO(d, SEG_ES, di, n, 1, FL(stos_rep_io));
		if (n == 1 && dir > 0) FMEMSET(d, v, cnt);
		else for (uword i = 0; i < cnt; i++, d += dir) {
			if (n == 1) fs8(d, v); else if (n == 2) fs16(d, v); else fs32(d, v);
		}
		goto FL(stos_rep_next);
FL(stos_rep_io): {   // MMIO (video memory): this page's part, element by element
		uword pa = fast_mmio_addr(cpu, mlin, n, 1);
		if (pa == (uword) -1) goto slow;
		FV_SKIP;
		for (uword i = 0; i < cnt; i++) fast_io_write(cpu, pa + i * dir, n, v);
	}
FL(stos_rep_next):
		SET_DI(di + cnt * dir);
		SET_CX(CX_ - cnt);
	}
	NEXT; }
FL(op_lodsb): strn = 1; goto FL(lods);
FL(op_lods): strn = opsz16 ? 2 : 4;
FL(lods): { int n = strn;
	if (rep) goto slow;
	int dir = (cpu->flags & DF) ? -n : n;
	u8 *s; FPTR_IO(s, STR_SEG, SI_, n, 0, FL(lods_io));
	if (n == 1) fw8(0, fm8(s)); else if (n == 2) sreg16(0, fm16(s)); else sreg32(0, fm32(s));
	SET_SI(SI_ + dir);
	NEXT;
FL(lods_io): {
		uword pa = fast_mmio_addr(cpu, mlin, n, 0);
		if (pa == (uword) -1) goto slow;
		FV_SKIP;
		u32 v = fast_io_read(cpu, pa, n);
		if (n == 1) fw8(0, v); else if (n == 2) sreg16(0, v); else sreg32(0, v);
		SET_SI(SI_ + dir);
		NEXT;
	}
	}
FL(op_scasb): strn = 1; goto FL(scas);
FL(op_scas): strn = opsz16 ? 2 : 4;
FL(scas): { int n = strn;
	int dir = (cpu->flags & DF) ? -n : n;
	do {
		if (rep && !CX_) break;
		u8 *d; FPTR(d, SEG_ES, DI_, n, 0);
		SET_DI(DI_ + dir);
		if (rep) SET_CX(CX_ - 1);
		if (n == 1) { u8 a = fr8(0), b = fm8(d); FCMPb(a, b, limm, 0, limm, 0) }
		else if (n == 2) { u16 a = lreg16(0), b = fm16(d); FCMPw(a, b, limm, 0, limm, 0) }
		else { u32 a = lreg32(0), b = fm32(d); FCMPd(a, b, limm, 0, limm, 0) }
		if (rep && ((cpu->cc.dst == 0) == (rep == 2))) break;
	} while (rep);
	NEXT; }
FL(op_cmpsb): strn = 1; goto FL(cmps);
FL(op_cmps): strn = opsz16 ? 2 : 4;
FL(cmps): { int n = strn;
	int dir = (cpu->flags & DF) ? -n : n;
	int ss = STR_SEG;
	do {
		if (rep && !CX_) break;
		u8 *s, *d;
		FPTR(s, ss, SI_, n, 0);
		FPTR(d, SEG_ES, DI_, n, 0);
		SET_SI(SI_ + dir);
		SET_DI(DI_ + dir);
		if (rep) SET_CX(CX_ - 1);
		if (n == 1) { u8 a = fm8(s), b = fm8(d); FCMPb(a, b, limm, 0, limm, 0) }
		else if (n == 2) { u16 a = fm16(s), b = fm16(d); FCMPw(a, b, limm, 0, limm, 0) }
		else { u32 a = fm32(s), b = fm32(d); FCMPd(a, b, limm, 0, limm, 0) }
		if (rep && ((cpu->cc.dst == 0) == (rep == 2))) break;
	} while (rep);
	NEXT; }

	// port I/O without permission checks (real mode, or CPL <= IOPL)
#define IO_ALLOWED (!PMODE || (!(cpu->flags & VM) && cpu->cpl <= get_IOPL(cpu)))
FL(op_in_ib): FL(op_in_dx): {
	if (!IO_ALLOWED) goto slow;
	FV_SKIP;
	u8 b = pc[-1];
	int port = b < 0xe8 ? *pc++ : lreg16(2);
	if (!(b & 1)) fw8(0, cpu->cb.io_read8(cpu->cb.io, port));
	else if (opsz16) sreg16(0, cpu->cb.io_read16(cpu->cb.io, port));
	else sreg32(0, cpu->cb.io_read32(cpu->cb.io, port));
	NEXT; }
FL(op_out_ib): FL(op_out_dx): {
	if (!IO_ALLOWED) goto slow;
	FV_SKIP;
	u8 b = pc[-1];
	int port = b < 0xe8 ? *pc++ : lreg16(2);
	if (!(b & 1)) cpu->cb.io_write8(cpu->cb.io, port, fr8(0));
	else if (opsz16) cpu->cb.io_write16(cpu->cb.io, port, lreg16(0));
	else cpu->cb.io_write32(cpu->cb.io, port, lreg32(0));
	NEXT; }

	// two-byte opcodes
FL(op_imul_r): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { IMUL2w(r, rm, lreg16, sreg16, lreg16, sreg16) }
		else { IMUL2d(r, rm, lreg32, sreg32, lreg32, sreg32) }
	} else if (opsz16) { u8 *p; EA_PTR(p, m, 2, 0); IMUL2w(r, p, lreg16, sreg16, fm16, fs16) }
	else { u8 *p; EA_PTR(p, m, 4, 0); IMUL2d(r, p, lreg32, sreg32, fm32, fs32) }
	NEXT; }
FL(op_movzx_b): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	u8 v;
	if (m >= 0xc0) v = fr8(rm); else { u8 *p; EA_PTR(p, m, 1, 0); v = fm8(p); }
	if (opsz16) sreg16(r, v); else sreg32(r, v);
	NEXT; }
FL(op_movzx_w): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	u16 v;
	if (m >= 0xc0) v = lreg16(rm); else { u8 *p; EA_PTR(p, m, 2, 0); v = fm16(p); }
	if (opsz16) sreg16(r, v); else sreg32(r, v);
	NEXT; }
FL(op_movsx_b): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	u8 v;
	if (m >= 0xc0) v = fr8(rm); else { u8 *p; EA_PTR(p, m, 1, 0); v = fm8(p); }
	if (opsz16) sreg16(r, sext8(v)); else sreg32(r, sext8(v));
	NEXT; }
FL(op_movsx_w): { u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	u16 v;
	if (m >= 0xc0) v = lreg16(rm); else { u8 *p; EA_PTR(p, m, 2, 0); v = fm16(p); }
	if (opsz16) sreg16(r, v); else sreg32(r, sext16(v));
	NEXT; }
FL(op_bsf): FL(op_bsr): { u8 b = pc[-1]; u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { if (b == 0xbc) { BSFw(r, rm, lreg16, sreg16, lreg16, sreg16) } else { BSRw(r, rm, lreg16, sreg16, lreg16, sreg16) } }
		else { if (b == 0xbc) { BSFd(r, rm, lreg32, sreg32, lreg32, sreg32) } else { BSRd(r, rm, lreg32, sreg32, lreg32, sreg32) } }
	} else if (opsz16) {
		u8 *p; EA_PTR(p, m, 2, 0);
		if (b == 0xbc) { BSFw(r, p, lreg16, sreg16, fm16, fs16) } else { BSRw(r, p, lreg16, sreg16, fm16, fs16) }
	} else {
		u8 *p; EA_PTR(p, m, 4, 0);
		if (b == 0xbc) { BSFd(r, p, lreg32, sreg32, fm32, fs32) } else { BSRd(r, p, lreg32, sreg32, fm32, fs32) }
	}
	NEXT; }
	// BT BTS BTR BTC Ev,Gv (the bit offset may reach beyond the operand in memory)
#define BT_OPS(A, X, Y, LA, SA, LB, SB) \
		switch (b) { \
		case 0xa3: { BT##A(X, Y, LA, SA, LB, SB) } break; \
		case 0xab: { BTS##A(X, Y, LA, SA, LB, SB) } break; \
		case 0xb3: { BTR##A(X, Y, LA, SA, LB, SB) } break; \
		default: { BTC##A(X, Y, LA, SA, LB, SB) } break; \
		}
FL(op_bt): { u8 b = pc[-1]; u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7;
	if (m >= 0xc0) {
		if (opsz16) { BT_OPS(w, rm, r, lreg16, sreg16, lreg16, sreg16) }
		else { BT_OPS(d, rm, r, lreg32, sreg32, lreg32, sreg32) }
	} else {
		seg = SEG_OVERRIDE;
		uword off = fast_ea(cpu, &pc, m, adsz16, &seg);
		u8 *p;
		if (opsz16) {
			off += lreg16(r) / 16 * 2;
			FPTR(p, seg, off, 2, b != 0xa3);
			BT_OPS(w, p, r, fm16, fs16, lreg16, sreg16)
		} else {
			off += lreg32(r) / 32 * 4;
			FPTR(p, seg, off, 4, b != 0xa3);
			BT_OPS(d, p, r, fm32, fs32, lreg32, sreg32)
		}
	}
	NEXT; }
FL(op_bt_ib): { u8 m = *pc++; int op = (m >> 3) & 7, rm = m & 7;   // 0F BA /4-7 Ev,Ib
	if (op < 4) goto slow;
	u8 b = op == 4 ? 0xa3 : op == 5 ? 0xab : op == 6 ? 0xb3 : 0xbb;
	if (m >= 0xc0) {
		u8 i = *pc++;
		if (opsz16) { BT_OPS(w, rm, i, lreg16, sreg16, limm, 0) }
		else { BT_OPS(d, rm, i, lreg32, sreg32, limm, 0) }
	} else if (opsz16) {
		u8 *p; EA_PTR(p, m, 2, op != 4);
		u8 i = *pc++;
		BT_OPS(w, p, i, fm16, fs16, limm, 0)
	} else {
		u8 *p; EA_PTR(p, m, 4, op != 4);
		u8 i = *pc++;
		BT_OPS(d, p, i, fm32, fs32, limm, 0)
	}
	NEXT; }
	// SHLD/SHRD Ev,Gv,Ib|CL
#define SHxD(OP) { u8 b = pc[-1]; u8 m = *pc++; int r = (m >> 3) & 7, rm = m & 7; \
	if (m >= 0xc0) { \
		u8 c = (b & 1) ? fr8(1) : *pc++; \
		if (opsz16) { OP##w(rm, r, c, lreg16, sreg16, lreg16, sreg16, limm, 0) } \
		else { OP##d(rm, r, c, lreg32, sreg32, lreg32, sreg32, limm, 0) } \
	} else if (opsz16) { \
		u8 *p; EA_PTR(p, m, 2, 1); \
		u8 c = (b & 1) ? fr8(1) : *pc++; \
		OP##w(p, r, c, fm16, fs16, lreg16, sreg16, limm, 0) \
	} else { \
		u8 *p; EA_PTR(p, m, 4, 1); \
		u8 c = (b & 1) ? fr8(1) : *pc++; \
		OP##d(p, r, c, fm32, fs32, lreg32, sreg32, limm, 0) \
	} \
	NEXT; }
FL(op_shld): SHxD(SHLD)
FL(op_shrd): SHxD(SHRD)

