#ifdef SIMD_i386ins_def
#ifdef I2
// MMX
I2(C(0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
     0x68, 0x69, 0x6a, 0x6b, 0x74, 0x75, 0x76),       _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(      0xd1, 0xd2, 0xd3,       0xd5,
     0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
     0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(      0xf1, 0xf2, 0xf3,       0xf5, 0xf6,
     0xf8, 0xf9, 0xfa,       0xfc, 0xfd, 0xfe),       _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(0x71, 0x72, 0x73), _ /*PqIb*/, 0, SIMD_GRPA)
I2(C(0x6e), _ /*PqEd*/, 1, SIMD_LOAD)
I2(C(0x7e), _ /*EdPq*/, 2, SIMD_STORE)
I2(C(0x6f), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(0x7f, 0xe7), _ /*QqPq*/, 2, SIMD_QqPq)
I2(C(0x77), _,  0, EMMS)
I2(C(0xc4), _, 0, SIMD_PINSRW)
I2(C(0xc5), _, 0, SIMD_PEXTRW)
I2(C(0x70), _, 0, SIMD_PSHUFW)
I2(C(0xd7), _, 0, SIMD_PMOVMSKB)
I2(C(0xf7), _, 0, SIMD_MASKMOVQ)

// SSE
#ifdef I386_ENABLE_SSE
I2(C(0x10,       0x12,             0x14, 0x15, 0x16, 0x28), _, 1, SIMD_VxWx)
I2(C(0x2e, 0x2f), _, 1, SIMD_VxWx_S)
I2(C(      0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
     0x58, 0x59,             0x5c, 0x5d, 0x5e, 0x5f), _, 1, SIMD_VxWx)
I2(C(0x11, 0x13, 0x17, 0x29, 0x2b), _, 1, SIMD_WxVx)
I2(C(0xc2, 0xc6), _, 1, SIMD_VxWxIb)
I2(C(0x2a), _, 1, SIMD_CVTI2S)
I2(C(0x2c, 0x2d), _, 1, SIMD_CVTS2I)
I2(C(0x50), _, 0, SIMD_MOVMSKP)
I2(C(0x18), _, 0, SIMD_PREFETCH)
I2(C(0xae), _, 0, SIMD_GRP15)
#endif /* I386_ENABLE_SSE */
#endif /* I2 */
#endif /* SIMD_i386ins_def */

#if defined(SIMD_i386_c) || defined(SIMD_fpu_c)
// MMX
bool fpu_mmx_rr(FPU *fpu, void *cpu, int op, int dst, int src);
bool fpu_mmx_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr);
bool fpu_mmx_ri(FPU *fpu, void *cpu, int op, int func, int dst, int imm);
bool fpu_mmx_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr);
uint64_t fpu_mmx_get(FPU *fpu, int i);
void fpu_mmx_set(FPU *fpu, int i, uint64_t v);

// SSE
#ifdef I386_ENABLE_SSE
void fpu_xmmsf32_set_s32(FPU *fpu, int dst, uint32_t v);
void fpu_xmmpf32_set_s32(FPU *fpu, int dst, uint64_t v);
float *fpu_xmm_get_f32(FPU *fpu, int i);
uint32_t *fpu_xmm_get_u32(FPU *fpu, int i);
bool fpu_xmmsf32_rr(FPU *fpu, void *cpu, int op, int dst, int src);
bool fpu_xmmsf32_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr);
bool fpu_xmmsf32_rri(FPU *fpu, void *cpu, int op, int func, int dst, int imm);
bool fpu_xmmsf32_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr);
bool fpu_xmmpf32_rr(FPU *fpu, void *cpu, int op, int dst, int src);
bool fpu_xmmpf32_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr);
bool fpu_xmmpf32_rri(FPU *fpu, void *cpu, int op, int func, int dst, int imm);
bool fpu_xmmpf32_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr);
bool fpu_xmm_grp15(FPU *fpu, void *cpu, int op, int seg, uint32_t addr);
#endif /* I386_ENABLE_SSE */
#endif /* defined(SIMD_i386_c) || defined(SIMD_fpu_c) */

#ifdef SIMD_i386_c
// MMX
#define SIMD_PqQq() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		TRY(fpu_mmx_rr(cpu->fpu, cpu, b1, reg, rm)); \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fpu_mmx_rm(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
	}

#define SIMD_QqPq() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		TRY(fpu_mmx_rr(cpu->fpu, cpu, b1, rm, reg)); \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fpu_mmx_mr(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
	}

#define SIMD_GRPA() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		TRY(fpu_mmx_ri(cpu->fpu, cpu, b1, (modrm >> 3) & 7, rm, imm8)); \
	} else { \
		THROW0(EX_UD); \
	}

#define SIMD_LOAD() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		fpu_mmx_set(cpu->fpu, reg, REGi(rm)); \
	} else { \
		uint32_t lo; \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(cpu_load32(cpu, curr_seg, addr, &lo)); \
		fpu_mmx_set(cpu->fpu, reg, lo); \
	}

#define SIMD_STORE() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		REGi(rm) = fpu_mmx_get(cpu->fpu, reg); \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		uint64_t v = fpu_mmx_get(cpu->fpu, reg); \
		TRY(cpu_store32(cpu, curr_seg, addr, v)); \
	}

#define EMMS()

// actually SSE
#define SIMD_PINSRW() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		int sh = (imm8 & 3) * 16; \
		uint64_t mask = 0xffffull << sh; \
		uint64_t v = (((uint64_t) REGi(rm)) << sh) & mask; \
		uint64_t w = fpu_mmx_get(cpu->fpu, reg) & ~mask; \
		fpu_mmx_set(cpu->fpu, reg, v | w); \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fetch8(cpu, &imm8)); \
		TRY(translate16(cpu, &meml, 1, curr_seg, addr)); \
		int sh = (imm8 & 3) * 16; \
		uint64_t mask = 0xffffull << sh; \
		uint64_t v = (((uint64_t) laddr16(&meml)) << sh) & mask; \
		uint64_t w = fpu_mmx_get(cpu->fpu, reg) & ~mask; \
		fpu_mmx_set(cpu->fpu, reg, v | w); \
	}

#define SIMD_PEXTRW() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		uint64_t v = fpu_mmx_get(cpu->fpu, rm); \
		REGi(reg) = (v >> ((imm8 & 3) * 16)) & 0xffff; \
	} else { \
		THROW0(EX_UD); \
	}

#define SIMD_PSHUFW() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		uint64_t s = fpu_mmx_get(cpu->fpu, rm); \
		uint64_t w = 0; \
		w |= (s >> (((imm8 >> 0) & 3) * 16) & 0xffff) << 0; \
		w |= (s >> (((imm8 >> 2) & 3) * 16) & 0xffff) << 16; \
		w |= (s >> (((imm8 >> 4) & 3) * 16) & 0xffff) << 32; \
		w |= (s >> (((imm8 >> 6) & 3) * 16) & 0xffff) << 48; \
		fpu_mmx_set(cpu->fpu, reg, w); \
	} else { \
		uint64_t s; \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fetch8(cpu, &imm8)); \
		TRY(translate32(cpu, &meml, 1, curr_seg, addr)); \
		s = laddr32(&meml); \
		TRY(translate32(cpu, &meml, 1, curr_seg, addr + 4)); \
		s |= ((uint64_t) laddr32(&meml)) << 32; \
		uint64_t w = 0; \
		w |= (s >> (((imm8 >> 0) & 3) * 16) & 0xffff) << 0; \
		w |= (s >> (((imm8 >> 2) & 3) * 16) & 0xffff) << 16; \
		w |= (s >> (((imm8 >> 4) & 3) * 16) & 0xffff) << 32; \
		w |= (s >> (((imm8 >> 6) & 3) * 16) & 0xffff) << 48; \
		fpu_mmx_set(cpu->fpu, reg, w); \
	}

#define SIMD_PMOVMSKB() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		uint64_t v = fpu_mmx_get(cpu->fpu, rm); \
		REGi(reg) = \
			((v >> 7) & 1) | ((v >> 14) & 2) | \
			((v >> 21) & 4) |((v >> 28) & 8) | \
			((v >> 35) & 16) | ((v >> 42) & 32) | \
			((v >> 49) & 64) |((v >> 56) & 128); \
	} else { \
		THROW0(EX_UD); \
	}

#define SIMD_MASKMOVQ() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		uint64_t mm1 = fpu_mmx_get(cpu->fpu, reg); \
		uint64_t mm2 = fpu_mmx_get(cpu->fpu, rm); \
		for (int i = 0; i < 8; i++) { \
			if ((mm2 >> 7) & 1) { \
				uword addr = REGi(7) + i; \
				if (adsz16) addr = addr & 0xffff; \
				TRY(cpu_store8(cpu, SEG_DS, addr, mm1)); \
			} \
			mm1 >>= 8; \
			mm2 >>= 8; \
		} \
	} else { \
		THROW0(EX_UD); \
	}

// SSE
#ifdef I386_ENABLE_SSE
#define SIMD_VxWx() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmpf32_rr(cpu->fpu, cpu, b1, reg, rm)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			TRY(fpu_xmmsf32_rr(cpu->fpu, cpu, b1, reg, rm)); \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmpf32_rm(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			TRY(fpu_xmmsf32_rm(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
		} else { \
			THROW0(EX_UD); \
		} \
	}

#define SIMD_VxWx_S() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmsf32_rr(cpu->fpu, cpu, b1, reg, rm)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmsf32_rm(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else { \
			THROW0(EX_UD); \
		} \
	}

#define SIMD_WxVx() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmpf32_rr(cpu->fpu, cpu, b1, rm, reg)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			TRY(fpu_xmmsf32_rr(cpu->fpu, cpu, b1, rm, reg)); \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmpf32_mr(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			TRY(fpu_xmmsf32_mr(cpu->fpu, cpu, b1, reg, curr_seg, addr)); \
		} else { \
			THROW0(EX_UD); \
		} \
	}

#define SIMD_VxWxIb() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	u8 imm8; \
	if (mod == 3) { \
		TRY(fetch8(cpu, &imm8)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				TRY(fpu_xmmpf32_rri(cpu->fpu, cpu, b1, (modrm >> 3) & 7, rm, imm8)); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			TRY(fpu_xmmsf32_rri(cpu->fpu, cpu, b1, (modrm >> 3) & 7, rm, imm8)); \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		THROW0(EX_UD); \
	}

#define SIMD_CVTI2S() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				uint64_t v = fpu_mmx_get(cpu->fpu, rm); \
				fpu_xmmpf32_set_s32(cpu->fpu, reg, v); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			fpu_xmmsf32_set_s32(cpu->fpu, reg, REGi(rm)); \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				uint32_t lo, hi; \
				TRY(cpu_load32(cpu, curr_seg, addr, &lo)); \
				TRY(cpu_load32(cpu, curr_seg, addr + 4, &hi)); \
				uint64_t v = (((uint64_t) hi) << 32) | lo; \
				fpu_xmmpf32_set_s32(cpu->fpu, reg, v); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			uint32_t v; \
			TRY(cpu_load32(cpu, curr_seg, addr, &v)); \
			fpu_xmmsf32_set_s32(cpu->fpu, reg, v); \
		} else { \
			THROW0(EX_UD); \
		} \
	}

#include <tgmath.h>
#define SIMD_CVTS2I() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				float *vv = fpu_xmm_get_f32(cpu->fpu, rm); \
				float d[2]; \
				d[0] = vv[0]; \
				d[1] = vv[1]; \
				/* TODO: respect mxcsr */ \
				if (b1 == 0x2d) { \
					d[0] = nearbyint(d[0]); \
					d[1] = nearbyint(d[1]); \
				} \
				uint32_t lo = (int32_t) d[0]; \
				uint32_t hi = (int32_t) d[1]; \
				uint64_t v = (((uint64_t) hi) << 32) | lo; \
				fpu_mmx_set(cpu->fpu, reg, v); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			float v = fpu_xmm_get_f32(cpu->fpu, rm)[0]; \
			/* TODO: respect mxcsr */ \
			if (b1 == 0x2d) { \
				v = nearbyint(v); \
			} \
			REGi(reg) = (int32_t) v; \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				union {float f; uint32_t v;} u[2]; \
				TRY(cpu_load32(cpu, curr_seg, addr, &(u[0].v))); \
				TRY(cpu_load32(cpu, curr_seg, addr, &(u[1].v))); \
				/* TODO: respect mxcsr */ \
				if (b1 == 0x2d) { \
					u[0].f = nearbyint(u[0].f); \
					u[1].f = nearbyint(u[1].f); \
				} \
				uint32_t lo = (int32_t) u[0].f; \
				uint32_t hi = (int32_t) u[1].f; \
				uint64_t v = (((uint64_t) hi) << 32) | lo; \
				fpu_mmx_set(cpu->fpu, reg, v); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else if (rep == 1) /* F3 */ { \
			union {float f; uint32_t v;} u; \
			TRY(cpu_load32(cpu, curr_seg, addr, &(u.v))); \
			/* TODO: respect mxcsr */ \
			if (b1 == 0x2d) { \
				u.f = nearbyint(u.f); \
			} \
			REGi(reg) = (int32_t) u.f; \
		} else { \
			THROW0(EX_UD); \
		} \
	}

#define SIMD_MOVMSKP() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int reg = (modrm >> 3) & 7; \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod == 3) { \
		if (rep == 0) { \
			if (opsz16 == code16) /* NP */ { \
				uint32_t *v = fpu_xmm_get_u32(cpu->fpu, rm); \
				REGi(reg) = \
					((v[0] >> 31) & 1) | \
					((v[1] >> 30) & 2) | \
					((v[2] >> 29) & 4) | \
					((v[3] >> 28) & 8); \
			} else /* 66 */ { \
				THROW0(EX_UD); \
			} \
		} else { \
			THROW0(EX_UD); \
		} \
	} else { \
		THROW0(EX_UD); \
	}

#define SIMD_GRP15() \
	if (cpu->cr0 & 0xc) THROW0(EX_NM); \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (modrm == 0xf8) { \
		/* SFENCE */ \
	} else if (mod == 3) { \
		THROW0(EX_UD); \
	} else { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
		TRY(fpu_xmm_grp15(cpu->fpu, cpu, (modrm >> 3) & 7, curr_seg, addr)); \
	}

#define SIMD_PREFETCH() \
	TRY(fetch8(cpu, &modrm)); \
	int mod = modrm >> 6; \
	int rm = modrm & 7; \
	if (mod != 3) { \
		TRY(modsib(cpu, adsz16, mod, rm, &addr, &curr_seg)); \
	}

#endif /* I386_ENABLE_SSE */
#endif /* SIMD_i386_c */

#ifdef SIMD_fpu_c
// MMX
static F80 *fpu_mm(FPU *fpu, int i)
{
	if (fpu->rawtagw & (1 << i)) {
		fpu->rawst[i] = tof80(fpu->st[i]);
		fpu->rawtagw &= ~(1 << i);
	}
	fpu->rawtagr &= ~(1 << i);
	return fpu->rawst + i;
}

typedef union {
	uint64_t v;
	uint64_t u64v[1];
	uint32_t u32v[2];
	uint16_t u16v[4];
	uint8_t u8v[8];
	int64_t s64v[1];
	int32_t s32v[2];
	int16_t s16v[4];
	int8_t s8v[8];
} UMMX;

#define MMX_v8_v(us, NAME) \
static uint64_t NAME ## 8(uint64_t a, uint64_t b) \
{ \
	UMMX v = { .v = a }; \
	UMMX w = { .v = b }; \
	NAME ## _(8, v. us ## 8v[0], w. us ## 8v[0]) \
	NAME ## _(8, v. us ## 8v[1], w. us ## 8v[1]) \
	NAME ## _(8, v. us ## 8v[2], w. us ## 8v[2]) \
	NAME ## _(8, v. us ## 8v[3], w. us ## 8v[3]) \
	NAME ## _(8, v. us ## 8v[4], w. us ## 8v[4]) \
	NAME ## _(8, v. us ## 8v[5], w. us ## 8v[5]) \
	NAME ## _(8, v. us ## 8v[6], w. us ## 8v[6]) \
	NAME ## _(8, v. us ## 8v[7], w. us ## 8v[7]) \
	return v.v; \
}

#define MMX_v16_v(us, NAME) \
static uint64_t NAME ## 16(uint64_t a, uint64_t b) \
{ \
	UMMX v = { .v = a }; \
	UMMX w = { .v = b }; \
	NAME ## _(16, v. us ## 16v[0], w. us ## 16v[0]) \
	NAME ## _(16, v. us ## 16v[1], w. us ## 16v[1]) \
	NAME ## _(16, v. us ## 16v[2], w. us ## 16v[2]) \
	NAME ## _(16, v. us ## 16v[3], w. us ## 16v[3]) \
	return v.v; \
}

#define MMX_v32_v(us, NAME) \
static uint64_t NAME ## 32(uint64_t a, uint64_t b) \
{ \
	UMMX v = { .v = a }; \
	UMMX w = { .v = b }; \
	NAME ## _(32, v. us ## 32v[0], w. us ## 32v[0]) \
	NAME ## _(32, v. us ## 32v[1], w. us ## 32v[1]) \
	return v.v; \
}

#define MMX_v64_v(us, NAME) \
static uint64_t NAME ## 64(uint64_t a, uint64_t b) \
{ \
	UMMX v = { .v = a }; \
	UMMX w = { .v = b }; \
	NAME ## _(64, v. us ## 64v[0], w. us ## 64v[0]) \
	return v.v; \
}

#define MMX_v_v(us, NAME) \
	MMX_v8_v(us, NAME) MMX_v16_v(us, NAME) MMX_v32_v(us, NAME)

#define MMX_v16_i(us, NAME) \
static uint64_t NAME ## 16(uint64_t a, int b) \
{ \
	UMMX v = { .v = a }; \
	NAME ## _(16, v. us ## 16v[0], b) \
	NAME ## _(16, v. us ## 16v[1], b) \
	NAME ## _(16, v. us ## 16v[2], b) \
	NAME ## _(16, v. us ## 16v[3], b) \
	return v.v; \
}

#define MMX_v32_i(us, NAME) \
static uint64_t NAME ## 32(uint64_t a, int b) \
{ \
	UMMX v = { .v = a }; \
	NAME ## _(32, v. us ## 32v[0], b) \
	NAME ## _(32, v. us ## 32v[1], b) \
	return v.v; \
}

#define MMX_v64_i(us, NAME) \
static uint64_t NAME ## 64(uint64_t a, int b) \
{ \
	UMMX v = { .v = a }; \
	NAME ## _(64, v. us ## 64v[0], b) \
	return v.v; \
}

#define MMX_v_i(us, NAME) \
	MMX_v16_i(us, NAME) MMX_v32_i(us, NAME) MMX_v64_i(us, NAME)

static inline uint8_t satu8(int a)
{
	return a > 255 ? 255 : a < 0 ? 0 : a;
}

static inline uint16_t satu16(int a)
{
	return a > 65535 ? 65535 : a < 0 ? 0 : a;
}

static inline int8_t sats8(int a)
{
	return a > 127 ? 127 : a < -128 ? -128 : a;
}

static inline int16_t sats16(int a)
{
	return a > 32767 ? 32767 : a < -32768 ? -32768 : a;
}

static inline int16_t his16(int a)
{
	return a >> 16;
}

static inline uint16_t hiu16(unsigned a)
{
	return a >> 16;
}

#define PADD_(B, a, b) a = a + b;
#define PSUB_(B, a, b) a = a - b;
#define PADDS_(B, a, b) a = sats ## B((int) a + (int) b);
#define PADDUS_(B, a, b) a = satu ## B((int) a + (int) b);
#define PSUBS_(B, a, b) a = sats ## B((int) a - (int) b);
#define PSUBUS_(B, a, b) a = satu ## B((int) a - (int) b);
#define PMULL_(B, a, b) a = a * b;
#define PMULH_(B, a, b) a = his ## B((int) a * (int) b);
#define PMULHU_(B, a, b) a = hiu ## B((unsigned) a * (unsigned) b);
#define PAND_(B, a, b) a = a & b;
#define PANDN_(B, a, b) a = (~a) & b;
#define POR_(B, a, b) a = a | b;
#define PXOR_(B, a, b) a = a ^ b;
#define PSLL_(B, a, b) a = a << b;
#define PSRA_(B, a, b) a = a >> b;
#define PSRL_(B, a, b) a = a >> b;
#define PCMPEQ_(B, a, b) a = (a == b ? -1 : 0);
#define PCMPGT_(B, a, b) a = (a > b ? -1 : 0);

MMX_v_v(u, PADD)
MMX_v_v(u, PSUB)
MMX_v8_v(s, PADDS)
MMX_v16_v(s, PADDS)
MMX_v8_v(u, PADDUS)
MMX_v16_v(u, PADDUS)
MMX_v8_v(s, PSUBS)
MMX_v16_v(s, PSUBS)
MMX_v8_v(u, PSUBUS)
MMX_v16_v(u, PSUBUS)
MMX_v16_v(s, PMULL)
MMX_v16_v(s, PMULH)
MMX_v64_v(u, PAND)
MMX_v64_v(u, PANDN)
MMX_v64_v(u, POR)
MMX_v64_v(u, PXOR)
MMX_v_i(u, PSLL)
MMX_v_i(s, PSRA)
MMX_v_i(u, PSRL)
MMX_v_v(s, PCMPEQ)
MMX_v_v(s, PCMPGT)

#define PAVG_(B, a, b) a = ((int) a + (int) b + 1) >> 1;
#define PMAX_(B, a, b) a = a > b ? a : b;
#define PMIN_(B, a, b) a = a < b ? a : b;
#define _AD_(B, a, b) a = abs(a - b);
MMX_v8_v(u, PAVG)
MMX_v16_v(u, PAVG)
MMX_v8_v(u, PMAX) // u8
MMX_v16_v(s, PMAX) // s16
MMX_v8_v(u, PMIN) // u8
MMX_v16_v(s, PMIN) // s16
MMX_v16_v(u, PMULHU)
MMX_v8_v(u, _AD)

static uint64_t PMADDWD(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	int t[4];
	t[0] = (int) v.s16v[0] * (int) w.s16v[0];
	t[1] = (int) v.s16v[1] * (int) w.s16v[1];
	t[2] = (int) v.s16v[2] * (int) w.s16v[2];
	t[3] = (int) v.s16v[3] * (int) w.s16v[3];

	UMMX r;
	r.s32v[0] = t[0] + t[1];
	r.s32v[1] = t[2] + t[3];
	return r.v;
}

static uint64_t PACKSSWB(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s8v[0] = sats8(v.s16v[0]);
	r.s8v[1] = sats8(v.s16v[1]);
	r.s8v[2] = sats8(v.s16v[2]);
	r.s8v[3] = sats8(v.s16v[3]);
	r.s8v[4] = sats8(w.s16v[0]);
	r.s8v[5] = sats8(w.s16v[1]);
	r.s8v[6] = sats8(w.s16v[2]);
	r.s8v[7] = sats8(w.s16v[3]);
	return r.v;
}

static uint64_t PUNPCKLBW(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s8v[0] = v.s8v[0];
	r.s8v[1] = w.s8v[0];
	r.s8v[2] = v.s8v[1];
	r.s8v[3] = w.s8v[1];
	r.s8v[4] = v.s8v[2];
	r.s8v[5] = w.s8v[2];
	r.s8v[6] = v.s8v[3];
	r.s8v[7] = w.s8v[3];
	return r.v;
}

static uint64_t PUNPCKLWD(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s16v[0] = v.s16v[0];
	r.s16v[1] = w.s16v[0];
	r.s16v[2] = v.s16v[1];
	r.s16v[3] = w.s16v[1];
	return r.v;
}

static uint64_t PUNPCKLDQ(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s32v[0] = v.s32v[0];
	r.s32v[1] = w.s32v[0];
	return r.v;
}

static uint64_t PUNPCKHBW(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s8v[0] = v.s8v[4];
	r.s8v[1] = w.s8v[4];
	r.s8v[2] = v.s8v[5];
	r.s8v[3] = w.s8v[5];
	r.s8v[4] = v.s8v[6];
	r.s8v[5] = w.s8v[6];
	r.s8v[6] = v.s8v[7];
	r.s8v[7] = w.s8v[7];
	return r.v;
}

static uint64_t PUNPCKHWD(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s16v[0] = v.s16v[2];
	r.s16v[1] = w.s16v[2];
	r.s16v[2] = v.s16v[3];
	r.s16v[3] = w.s16v[3];
	return r.v;
}

static uint64_t PUNPCKHDQ(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s32v[0] = v.s32v[1];
	r.s32v[1] = w.s32v[1];
	return r.v;
}

static uint64_t PACKUSWB(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.u8v[0] = satu8(v.s16v[0]);
	r.u8v[1] = satu8(v.s16v[1]);
	r.u8v[2] = satu8(v.s16v[2]);
	r.u8v[3] = satu8(v.s16v[3]);
	r.u8v[4] = satu8(w.s16v[0]);
	r.u8v[5] = satu8(w.s16v[1]);
	r.u8v[6] = satu8(w.s16v[2]);
	r.u8v[7] = satu8(w.s16v[3]);
	return r.v;
}

static uint64_t PACKSSDW(uint64_t a, uint64_t b)
{
	UMMX v = { .v = a };
	UMMX w = { .v = b };
	UMMX r;
	r.s16v[0] = sats16(v.s32v[0]);
	r.s16v[1] = sats16(v.s32v[1]);
	r.s16v[2] = sats16(w.s32v[0]);
	r.s16v[3] = sats16(w.s32v[1]);
	return r.v;
}

static uint64_t PSADBW(uint64_t a, uint64_t b)
{
	UMMX v;
	v.v = _AD8(a, b);
	uint16_t s = 0;
	s += v.u8v[0];
	s += v.u8v[1];
	s += v.u8v[2];
	s += v.u8v[3];
	s += v.u8v[4];
	s += v.u8v[5];
	s += v.u8v[6];
	s += v.u8v[7];
	return s;
}

bool fpu_mmx_rr(FPU *fpu, void *cpu, int op, int dst, int src)
{
	uint64_t d = fpu_mmx_get(fpu, dst);
	uint64_t s = fpu_mmx_get(fpu, src);
	switch (op) {
	case 0x60: d = PUNPCKLBW(d, s); break;
	case 0x61: d = PUNPCKLWD(d, s); break;
	case 0x62: d = PUNPCKLDQ(d, s); break;
	case 0x63: d = PACKSSWB(d, s); break;
	case 0x64: d = PCMPGT8(d, s); break;
	case 0x65: d = PCMPGT16(d, s); break;
	case 0x66: d = PCMPGT32(d, s); break;
	case 0x67: d = PACKUSWB(d, s); break;
	case 0x68: d = PUNPCKHBW(d, s); break;
	case 0x69: d = PUNPCKHWD(d, s); break;
	case 0x6a: d = PUNPCKHDQ(d, s); break;
	case 0x6b: d = PACKSSDW(d, s); break;
	case 0x74: d = PCMPEQ8(d, s); break;
	case 0x75: d = PCMPEQ16(d, s); break;
	case 0x76: d = PCMPEQ32(d, s); break;
	case 0xd1: d = PSRL16(d, s); break;
	case 0xd2: d = PSRL32(d, s); break;
	case 0xd3: d = PSRL64(d, s); break;
	case 0xe1: d = PSRA16(d, s); break;
	case 0xe2: d = PSRA32(d, s); break;
	case 0xf1: d = PSLL16(d, s); break;
	case 0xf2: d = PSLL32(d, s); break;
	case 0xf3: d = PSLL64(d, s); break;
	case 0xd5: d = PMULL16(d, s); break;
	case 0xe5: d = PMULH16(d, s); break;
	case 0xf5: d = PMADDWD(d, s); break;
	case 0xd8: d = PSUBUS8(d, s); break;
	case 0xd9: d = PSUBUS16(d, s); break;
	case 0xe8: d = PSUBS8(d, s); break;
	case 0xe9: d = PSUBS16(d, s); break;
	case 0xf8: d = PSUB8(d, s); break;
	case 0xf9: d = PSUB16(d, s); break;
	case 0xfa: d = PSUB32(d, s); break;
	case 0xdb: d = PAND64(d, s); break;
	case 0xeb: d = POR64(d, s); break;
	case 0xdc: d = PADDUS8(d, s); break;
	case 0xdd: d = PADDUS16(d, s); break;
	case 0xec: d = PADDS8(d, s); break;
	case 0xed: d = PADDS16(d, s); break;
	case 0xfc: d = PADD8(d, s); break;
	case 0xfd: d = PADD16(d, s); break;
	case 0xfe: d = PADD32(d, s); break;
	case 0xdf: d = PANDN64(d, s); break;
	case 0xef: d = PXOR64(d, s); break;
	case 0x6f: case 0x7f: d = s; break;
	/* SSE */
	case 0xda: d = PMIN8(d, s); break;
	case 0xde: d = PMAX8(d, s); break;
	case 0xe0: d = PAVG8(d, s); break;
	case 0xe3: d = PAVG16(d, s); break;
	case 0xe4: d = PMULHU16(d, s); break;
	case 0xea: d = PMIN16(d, s); break;
	case 0xee: d = PMAX16(d, s); break;
	case 0xf6: d = PSADBW(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu_mmx_set(fpu, dst, d);
	return true;
}

bool fpu_mmx_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr)
{
	uint64_t d = fpu_mmx_get(fpu, dst);
	uint32_t lo, hi;
	if(!cpu_load32(cpu, seg, addr, &lo))
		return false;
	if(!cpu_load32(cpu, seg, addr + 4, &hi))
		return false;
	uint64_t s = (((uint64_t) hi) << 32) | lo;

	switch (op) {
	case 0x60: d = PUNPCKLBW(d, s); break;
	case 0x61: d = PUNPCKLWD(d, s); break;
	case 0x62: d = PUNPCKLDQ(d, s); break;
	case 0x63: d = PACKSSWB(d, s); break;
	case 0x64: d = PCMPGT8(d, s); break;
	case 0x65: d = PCMPGT16(d, s); break;
	case 0x66: d = PCMPGT32(d, s); break;
	case 0x67: d = PACKUSWB(d, s); break;
	case 0x68: d = PUNPCKHBW(d, s); break;
	case 0x69: d = PUNPCKHWD(d, s); break;
	case 0x6a: d = PUNPCKHDQ(d, s); break;
	case 0x6b: d = PACKSSDW(d, s); break;
	case 0x74: d = PCMPEQ8(d, s); break;
	case 0x75: d = PCMPEQ16(d, s); break;
	case 0x76: d = PCMPEQ32(d, s); break;
	case 0xd1: d = PSRL16(d, s); break;
	case 0xd2: d = PSRL32(d, s); break;
	case 0xd3: d = PSRL64(d, s); break;
	case 0xe1: d = PSRA16(d, s); break;
	case 0xe2: d = PSRA32(d, s); break;
	case 0xf1: d = PSLL16(d, s); break;
	case 0xf2: d = PSLL32(d, s); break;
	case 0xf3: d = PSLL64(d, s); break;
	case 0xd5: d = PMULL16(d, s); break;
	case 0xe5: d = PMULH16(d, s); break;
	case 0xf5: d = PMADDWD(d, s); break;
	case 0xd8: d = PSUBUS8(d, s); break;
	case 0xd9: d = PSUBUS16(d, s); break;
	case 0xe8: d = PSUBS8(d, s); break;
	case 0xe9: d = PSUBS16(d, s); break;
	case 0xf8: d = PSUB8(d, s); break;
	case 0xf9: d = PSUB16(d, s); break;
	case 0xfa: d = PSUB32(d, s); break;
	case 0xdb: d = PAND64(d, s); break;
	case 0xeb: d = POR64(d, s); break;
	case 0xdc: d = PADDUS8(d, s); break;
	case 0xdd: d = PADDUS16(d, s); break;
	case 0xec: d = PADDS8(d, s); break;
	case 0xed: d = PADDS16(d, s); break;
	case 0xfc: d = PADD8(d, s); break;
	case 0xfd: d = PADD16(d, s); break;
	case 0xfe: d = PADD32(d, s); break;
	case 0xdf: d = PANDN64(d, s); break;
	case 0xef: d = PXOR64(d, s); break;
	case 0x6f: d = s; break;
	/* SSE */
	case 0xda: d = PMIN8(d, s); break;
	case 0xde: d = PMAX8(d, s); break;
	case 0xe0: d = PAVG8(d, s); break;
	case 0xe3: d = PAVG16(d, s); break;
	case 0xe4: d = PMULHU16(d, s); break;
	case 0xea: d = PMIN16(d, s); break;
	case 0xee: d = PMAX16(d, s); break;
	case 0xf6: d = PSADBW(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu_mmx_set(fpu, dst, d);
	return true;
}

bool fpu_mmx_ri(FPU *fpu, void *cpu, int op, int func, int dst, int imm)
{
	uint64_t v = fpu_mmx_get(fpu, dst);
	switch (op) {
	case 0x71:
		switch (func) {
		case 2: v = PSRL16(v, imm); break;
		case 4: v = PSRA16(v, imm); break;
		case 6: v = PSLL16(v, imm); break;
		default:
			cpu_setexc(cpu, 6, 0);
			return false;
		}
		break;
	case 0x72:
		switch (func) {
		case 2: v = PSRL32(v, imm); break;
		case 4: v = PSRA32(v, imm); break;
		case 6: v = PSLL32(v, imm); break;
		default:
			cpu_setexc(cpu, 6, 0);
			return false;
		}
		break;
	case 0x73:
		switch (func) {
		case 2: v = PSRL64(v, imm); break;
		case 4: v = PSRA64(v, imm); break;
		case 6: v = PSLL64(v, imm); break;
		default:
			cpu_setexc(cpu, 6, 0);
			return false;
		}
		break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu_mmx_set(fpu, dst, v);
	return true;
}

bool fpu_mmx_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr)
{
	if (op == 0x7f || op == 0xe7) { // MOVQ/MOVNTQ
		F80 *v = fpu_mm(fpu, src);
		if (!cpu_store32(cpu, seg, addr, v->mant0))
			return false;
		if (!cpu_store32(cpu, seg, addr + 4, v->mant1))
			return false;
		return true;
	}
	cpu_setexc(cpu, 6, 0);
	return false;
}

uint64_t fpu_mmx_get(FPU *fpu, int i)
{
	F80 *v = fpu_mm(fpu, i);
	return v->mant0 | ((((uint64_t) v->mant1) << 32));
}

void fpu_mmx_set(FPU *fpu, int i, uint64_t v)
{
	F80 *d = fpu_mm(fpu, i);
	d->mant0 = v;
	d->mant1 = v >> 32;
	d->high = 0xffff;
}

// SSE
#ifdef I386_ENABLE_SSE
#define XMM_sf32(NAME) \
static UXMM NAME ## sf32(UXMM a, UXMM b) \
{ \
	NAME ## _(32, a.f32v[0], b.f32v[0]) \
	return a; \
}

#define XMM_sf32i(NAME) \
static UXMM NAME ## sf32(UXMM a, UXMM b) \
{ \
	NAME ## _(32, a.u32v[0], a.f32v[0], b.f32v[0]) \
	return a; \
}

#define XMM_pf32(NAME) \
static UXMM NAME ## pf32(UXMM a, UXMM b) \
{ \
	NAME ## _(32, a.f32v[0], b.f32v[0]) \
	NAME ## _(32, a.f32v[1], b.f32v[1]) \
	NAME ## _(32, a.f32v[2], b.f32v[2]) \
	NAME ## _(32, a.f32v[3], b.f32v[3]) \
	return a; \
}

#define XMM_pf32i(NAME) \
static UXMM NAME ## pf32(UXMM a, UXMM b) \
{ \
	NAME ## _(32, a.u32v[0], a.f32v[0], b.f32v[0]) \
	NAME ## _(32, a.u32v[1], a.f32v[1], b.f32v[1]) \
	NAME ## _(32, a.u32v[2], a.f32v[2], b.f32v[2]) \
	NAME ## _(32, a.u32v[3], a.f32v[3], b.f32v[3]) \
	return a; \
}

#define XMM_pu32(NAME) \
static UXMM NAME ## pu32(UXMM a, UXMM b) \
{ \
	NAME ## _(32, a.u32v[0], b.u32v[0]) \
	NAME ## _(32, a.u32v[1], b.u32v[1]) \
	NAME ## _(32, a.u32v[2], b.u32v[2]) \
	NAME ## _(32, a.u32v[3], b.u32v[3]) \
	return a; \
}

#define ADD_(B, a, b) a = a + b;
#define SUB_(B, a, b) a = a - b;
#define MUL_(B, a, b) a = a * b;
#define DIV_(B, a, b) a = a / b;
#define RCP_(B, a, b) a = 1.0 / b;
#define SQRT_(B, a, b) a = sqrt(b);
#define MAX_(B, a, b) a = a > b ? a : b;
#define MIN_(B, a, b) a = a < b ? a : b;
#define RSQRT_(B, a, b) a = 1.0 / sqrt(b);

#define AND_(B, a, b) a = a & b;
#define ANDN_(B, a, b) a = (~a) & b;
#define OR_(B, a, b) a = a | b;
#define XOR_(B, a, b) a = a ^ b;

#define CMPEQ_(B, c, a, b) c = (a == b ? -1 : 0);
#define CMPLT_(B, c, a, b) c = (a < b ? -1 : 0);
#define CMPLE_(B, c, a, b) c = (a <= b ? -1 : 0);
#define CMPNORD_(B, c, a, b) c = (isunordered(a, b) ? -1 : 0);
#define CMPNEQ_(B, c, a, b) c = (a != b ? -1 : 0);
#define CMPNLT_(B, c, a, b) c = (!(a < b) ? -1 : 0);
#define CMPNLE_(B, c, a, b) c = (!(a <= b) ? -1 : 0);
#define CMPORD_(B, c, a, b) c = (!isunordered(a, b) ? -1 : 0);

XMM_sf32(ADD)
XMM_sf32(SUB)
XMM_sf32(MUL)
XMM_sf32(DIV)
XMM_sf32(RCP)
XMM_sf32(SQRT)
XMM_sf32(MAX)
XMM_sf32(MIN)
XMM_sf32(RSQRT)

XMM_pf32(ADD)
XMM_pf32(SUB)
XMM_pf32(MUL)
XMM_pf32(DIV)
XMM_pf32(RCP)
XMM_pf32(SQRT)
XMM_pf32(MAX)
XMM_pf32(MIN)
XMM_pf32(RSQRT)

XMM_pu32(AND)
XMM_pu32(ANDN)
XMM_pu32(OR)
XMM_pu32(XOR)

XMM_sf32i(CMPEQ)
XMM_sf32i(CMPLT)
XMM_sf32i(CMPLE)
XMM_sf32i(CMPNORD)
XMM_sf32i(CMPNEQ)
XMM_sf32i(CMPNLT)
XMM_sf32i(CMPNLE)
XMM_sf32i(CMPORD)
XMM_pf32i(CMPEQ)
XMM_pf32i(CMPLT)
XMM_pf32i(CMPLE)
XMM_pf32i(CMPNORD)
XMM_pf32i(CMPNEQ)
XMM_pf32i(CMPNLT)
XMM_pf32i(CMPNLE)
XMM_pf32i(CMPORD)

static UXMM SHUFpf32(UXMM a, UXMM b, int imm)
{
	UXMM r;
	r.u32v[0] = a.u32v[(imm >> 0) & 3];
	r.u32v[1] = a.u32v[(imm >> 2) & 3];
	r.u32v[2] = b.u32v[(imm >> 4) & 3];
	r.u32v[3] = b.u32v[(imm >> 6) & 3];
	return r;
}

static UXMM UNPCKLpf32(UXMM a, UXMM b)
{
	UXMM r;
	r.u32v[0] = a.u32v[0];
	r.u32v[1] = b.u32v[0];
	r.u32v[2] = a.u32v[1];
	r.u32v[3] = b.u32v[1];
	return r;
}

static UXMM UNPCKHpf32(UXMM a, UXMM b)
{
	UXMM r;
	r.u32v[0] = a.u32v[2];
	r.u32v[1] = b.u32v[2];
	r.u32v[2] = a.u32v[3];
	r.u32v[3] = b.u32v[3];
	return r;
}

static void UCOMIsf32(void *cpu, UXMM d, UXMM s)
{
	double a = d.f32v[0];
	double b = s.f32v[0];
	if (isunordered(a, b)) {
		cpu_setflags(cpu, ZF | PF | CF, OF | AF | SF);
	} else if (a == b) {
		cpu_setflags(cpu, ZF, PF | CF | OF | AF | SF);
	} else if (a < b) {
		cpu_setflags(cpu, CF, ZF | PF | OF | AF | SF);
	} else {
		cpu_setflags(cpu, 0, ZF | PF | CF | OF | AF | SF);
	}
}

bool fpu_xmmsf32_rr(FPU *fpu, void *cpu, int op, int dst, int src)
{
	UXMM d = fpu->xmm[dst];
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0x10: d.u32v[0] = s.u32v[0]; break; // MOVSS
	case 0x2e: case 0x2f: UCOMIsf32(cpu, d, s); return true;

	case 0x58: d = ADDsf32(d, s); break;
	case 0x5c: d = SUBsf32(d, s); break;
	case 0x59: d = MULsf32(d, s); break;
	case 0x5e: d = DIVsf32(d, s); break;
	case 0x53: d = RCPsf32(d, s); break;
	case 0x51: d = SQRTsf32(d, s); break;
	case 0x5f: d = MAXsf32(d, s); break;
	case 0x5d: d = MINsf32(d, s); break;
	case 0x52: d = RSQRTsf32(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmsf32_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr)
{
	UXMM d = fpu->xmm[dst];
	UXMM s;
	if(!cpu_load32(cpu, seg, addr, s.u32v))
		return false;

	switch (op) {
	case 0x10: d.u32v[0] = s.u32v[0]; break; // MOVSS
	case 0x2e: case 0x2f: UCOMIsf32(cpu, d, s); return true;

	case 0x58: d = ADDsf32(d, s); break;
	case 0x5c: d = SUBsf32(d, s); break;
	case 0x59: d = MULsf32(d, s); break;
	case 0x5e: d = DIVsf32(d, s); break;
	case 0x53: d = RCPsf32(d, s); break;
	case 0x51: d = SQRTsf32(d, s); break;
	case 0x5f: d = MAXsf32(d, s); break;
	case 0x5d: d = MINsf32(d, s); break;
	case 0x52: d = RSQRTsf32(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmsf32_rri(FPU *fpu, void *cpu, int op, int dst, int src, int imm)
{
	UXMM d = fpu->xmm[dst];
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0xc2:
		switch(imm) {
		case 0: d = CMPEQsf32(d, s); break;
		case 1: d = CMPLTsf32(d, s); break;
		case 2: d = CMPLEsf32(d, s); break;
		case 3: d = CMPNORDsf32(d, s); break;
		case 4: d = CMPNEQsf32(d, s); break;
		case 5: d = CMPNLTsf32(d, s); break;
		case 6: d = CMPNLEsf32(d, s); break;
		case 7: d = CMPORDsf32(d, s); break;
		default:
			cpu_setexc(cpu, 6, 0);
			return false;
		}
		break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmsf32_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr)
{
	UXMM d;
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0x11: d.u32v[0] = s.u32v[0]; break; // MOVSS
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	if (!cpu_store32(cpu, seg, addr, d.u32v[0]))
		return false;
	return true;
}

bool fpu_xmmpf32_rr(FPU *fpu, void *cpu, int op, int dst, int src)
{
	UXMM d = fpu->xmm[dst];
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0x10: case 0x28: d = s; break; // MOVUPS/MOVAPS
	case 0x12: d.u32v[0] = s.u32v[2]; d.u32v[1] = s.u32v[3]; break; // MOVHLPS
	case 0x16: d.u32v[2] = s.u32v[0]; d.u32v[3] = s.u32v[1]; break; // MOVLHPS
	case 0x14: d = UNPCKLpf32(d, s); break;
	case 0x15: d = UNPCKHpf32(d, s); break;

	case 0x58: d = ADDpf32(d, s); break;
	case 0x5c: d = SUBpf32(d, s); break;
	case 0x59: d = MULpf32(d, s); break;
	case 0x5e: d = DIVpf32(d, s); break;
	case 0x53: d = RCPpf32(d, s); break;
	case 0x51: d = SQRTpf32(d, s); break;
	case 0x5f: d = MAXpf32(d, s); break;
	case 0x5d: d = MINpf32(d, s); break;
	case 0x52: d = RSQRTpf32(d, s); break;

	case 0x54: d = ANDpu32(d, s); break;
	case 0x55: d = ANDNpu32(d, s); break;
	case 0x56: d = ORpu32(d, s); break;
	case 0x57: d = XORpu32(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmpf32_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr)
{
	UXMM d = fpu->xmm[dst];
	UXMM s;
	int n = 4;
	if (op == 0x12 || op == 0x16) n = 2;
	for (int i = 0; i < n; i++)
		if(!cpu_load32(cpu, seg, addr + 4 * i, s.u32v + i))
			return false;

	switch (op) {
	case 0x10: case 0x28: d = s; break; // MOVUPS/MOVAPS
	case 0x12: d.u32v[0] = s.u32v[0]; d.u32v[1] = s.u32v[1]; break; // MOVLPS
	case 0x16: d.u32v[2] = s.u32v[0]; d.u32v[3] = s.u32v[1]; break; // MOVHPS
	case 0x14: d = UNPCKLpf32(d, s); break;
	case 0x15: d = UNPCKHpf32(d, s); break;

	case 0x58: d = ADDpf32(d, s); break;
	case 0x5c: d = SUBpf32(d, s); break;
	case 0x59: d = MULpf32(d, s); break;
	case 0x5e: d = DIVpf32(d, s); break;
	case 0x53: d = RCPpf32(d, s); break;
	case 0x51: d = SQRTpf32(d, s); break;
	case 0x5f: d = MAXpf32(d, s); break;
	case 0x5d: d = MINpf32(d, s); break;
	case 0x52: d = RSQRTpf32(d, s); break;

	case 0x54: d = ANDpu32(d, s); break;
	case 0x55: d = ANDNpu32(d, s); break;
	case 0x56: d = ORpu32(d, s); break;
	case 0x57: d = XORpu32(d, s); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmpf32_rri(FPU *fpu, void *cpu, int op, int dst, int src, int imm)
{
	UXMM d = fpu->xmm[dst];
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0xc2:
		switch(imm) {
		case 0: d = CMPEQpf32(d, s); break;
		case 1: d = CMPLTpf32(d, s); break;
		case 2: d = CMPLEpf32(d, s); break;
		case 3: d = CMPNORDpf32(d, s); break;
		case 4: d = CMPNEQpf32(d, s); break;
		case 5: d = CMPNLTpf32(d, s); break;
		case 6: d = CMPNLEpf32(d, s); break;
		case 7: d = CMPORDpf32(d, s); break;
		default:
			cpu_setexc(cpu, 6, 0);
			return false;
		}
		break;
	case 0xc6:
		d = SHUFpf32(d, s, imm); break;
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	fpu->xmm[dst] = d;
	return true;
}

bool fpu_xmmpf32_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr)
{
	UXMM d;
	UXMM s = fpu->xmm[src];
	switch (op) {
	case 0x11: case 0x29: case 0x2b: d = s; break; // MOVUPS/MOVAPS/MOVNTPS
	case 0x13: d.u32v[0] = s.u32v[0]; d.u32v[1] = s.u32v[1]; break; // MOVLPS
	case 0x17: d.u32v[0] = s.u32v[2]; d.u32v[1] = s.u32v[3]; break; // MOVHPS
	default:
		cpu_setexc(cpu, 6, 0);
		return false;
	}
	int n = 4;
	if (op == 0x13 || op == 0x17) n = 2;
	for (int i = 0; i < n; i++)
		if (!cpu_store32(cpu, seg, addr + 4 * i, d.u32v[i]))
			return false;
	return true;
}

void fpu_xmmsf32_set_s32(FPU *fpu, int dst, uint32_t v)
{
	fpu->xmm[dst].f32v[0] = (float) (int32_t) v;
}

void fpu_xmmpf32_set_s32(FPU *fpu, int dst, uint64_t v)
{
	UMMX w = {.v = v};
	fpu->xmm[dst].f32v[0] = (float) w.s32v[0];
	fpu->xmm[dst].f32v[1] = (float) w.s32v[1];
}

float *fpu_xmm_get_f32(FPU *fpu, int i)
{
	return fpu->xmm[i].f32v;
}

uint32_t *fpu_xmm_get_u32(FPU *fpu, int i)
{
	return fpu->xmm[i].u32v;
}

bool fpu_xmm_grp15(FPU *fpu, void *cpu, int op, int seg, uint32_t addr)
{
	switch (op) {
	case 0: { // FXSAVE
		uword start = addr;
		if(!cpu_store16(cpu, seg, addr, fpu->cw))
			return false;
		u16 sw = getsw(fpu);
		if(!cpu_store16(cpu, seg, addr + 2, sw))
			return false;
		if(!cpu_store32(cpu, seg, addr + 16 + 8, fpu->mxcsr))
			return false;
		start += 32;
		for (int j = 0; j < 8; j++) {
			if (fpu->rawtagw & (1 << j)) {
				fpu->rawst[j] = tof80(fpu->st[j]);
				fpu->rawtagw &= ~(1 << j);
			}
			if (!cpu_store32(cpu, seg, start,
					 fpu->rawst[j].mant0))
				return false;
			if (!cpu_store32(cpu, seg, start + 4,
					 fpu->rawst[j].mant1))
				return false;
			if (!cpu_store16(cpu, seg, start + 8,
					 fpu->rawst[j].high))
				return false;
			start += 16;
		}
		for (int j = 0; j < 8; j++) {
			for (int k = 0; k < 4; k++) {
				if (!cpu_store32(cpu, seg, start, fpu->xmm[j].u32v[k]))
					return false;
				start += 4;
			}
		}
		return true;
	}
	case 1: { // FXRSTOR
		uword start = addr;
		if (!cpu_load16(cpu, seg, addr, &(fpu->cw)))
			return false;
		u16 sw;
		if (!cpu_load16(cpu, seg, addr + 2, &sw))
			return false;
		setsw(fpu, sw);
		start += 32;
		for (int j = 0; j < 8; j++) {
			if (!cpu_load32(cpu, seg, start,
					&fpu->rawst[j].mant0))
				return false;
			if (!cpu_load32(cpu, seg, start + 4,
					&fpu->rawst[j].mant1))
				return false;
			if (!cpu_load16(cpu, seg, start + 8,
					&fpu->rawst[j].high))
				return false;
			fpu->rawtagr &= ~(1 << j);
			fpu->rawtagw &= ~(1 << j);
			start += 16;
		}
		for (int j = 0; j < 8; j++) {
			for (int k = 0; k < 4; k++) {
				if (!cpu_load32(cpu, seg, start, &fpu->xmm[j].u32v[k]))
					return false;
				start += 4;
			}
		}
		return true;
	}
	case 2: { // LDMXCSR
		uint32_t mxcsr;
		if (!cpu_load32(cpu, seg, addr, &mxcsr))
			return false;
		fpu->mxcsr = mxcsr;
		return true;
	}
	case 3: { // STMXCSR
		return cpu_store32(cpu, seg, addr, fpu->mxcsr);
	}
	}
	cpu_setexc(cpu, 6, 0);
	return false;
}
#endif /* I386_ENABLE_SSE */
#endif /* SIMD_fpu_c */
