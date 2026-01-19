#ifdef MMX_i386ins_def
#ifdef I2
I2(C(0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
     0x68, 0x69, 0x6a, 0x6b, 0x74, 0x75, 0x76),       _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(      0xd1, 0xd2, 0xd3,       0xd5,
     0xd8, 0xd9,       0xdb, 0xdc, 0xdd,       0xdf), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(      0xe1, 0xe2,             0xe5,
     0xe8, 0xe9,       0xeb, 0xec, 0xed,       0xef), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(      0xf1, 0xf2, 0xf3,       0xf5,
     0xf8, 0xf9, 0xfa,       0xfc, 0xfd, 0xfe),       _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(0x71, 0x72, 0x73), _ /*PqIb*/, 0, SIMD_GRPA)
I2(C(0x6e), _ /*PqEd*/, 1, SIMD_LOAD)
I2(C(0x7e), _ /*EdPq*/, 2, SIMD_STORE)
I2(C(0x6f), _ /*PqQq*/, 1, SIMD_PqQq)
I2(C(0x7f), _ /*QqPq*/, 2, SIMD_QqPq)
I2(C(0x77), _,  0, EMMS)
#endif
#endif

#if defined(MMX_i386_c) || defined(MMX_fpu_c)
bool fpu_mmx_rr(FPU *fpu, void *cpu, int op, int dst, int src);
bool fpu_mmx_rm(FPU *fpu, void *cpu, int op, int dst, int seg, uint32_t addr);
bool fpu_mmx_ri(FPU *fpu, void *cpu, int op, int func, int dst, int imm);
bool fpu_mmx_mr(FPU *fpu, void *cpu, int op, int src, int seg, uint32_t addr);
uint64_t fpu_mmx_get(FPU *fpu, int i);
void fpu_mmx_set(FPU *fpu, int i, uint64_t v);
#endif

#ifdef MMX_i386_c
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
#endif

#ifdef MMX_fpu_c
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

#define PADD_(B, a, b) a = a + b;
#define PSUB_(B, a, b) a = a - b;
#define PADDS_(B, a, b) a = sats ## B((int) a + (int) b);
#define PADDUS_(B, a, b) a = satu ## B((int) a + (int) b);
#define PSUBS_(B, a, b) a = sats ## B((int) a - (int) b);
#define PSUBUS_(B, a, b) a = satu ## B((int) a - (int) b);
#define PMULL_(B, a, b) a = a * b;
#define PMULH_(B, a, b) a = his ## B((int) a * (int) b);
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
	if (op == 0x7f) {
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
#endif
