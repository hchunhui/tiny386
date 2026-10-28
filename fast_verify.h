/*
 * FAST_VERIFY: each instruction the fast path completes is undone and redone by cpu_exec1, whose result is
 * kept; registers, flags, segments and the memory written are compared and differences printed.
 * (Writes only tiny386 makes aren't seen.)
 */
#include <stdio.h>

static struct { u8 *p; int len, off; } fv_log_e[1 << 20];
static u8 fv_old[1 << 24], fv_new[1 << 24];
static int fv_n, fv_oldn;
static bool fv_active;
static CPUI386 fv_snap;
static uword fv_ins;
static long fv_count, fv_bad;

static void fv_log(u8 *p, int len)
{
	if (fv_n == (int) (sizeof(fv_log_e) / sizeof(fv_log_e[0])) || fv_oldn + len > (int) sizeof(fv_old)) {
		fprintf(stderr, "fast verify: write log full\n");
		abort();
	}
	fv_log_e[fv_n].p = p;
	fv_log_e[fv_n].len = len;
	fv_log_e[fv_n].off = fv_oldn;
	memcpy(fv_old + fv_oldn, p, len);
	fv_oldn += len;
	fv_n++;
}
#define fs8(p, v) (fv_log((u8 *) (p), 1), *(u8 *) (p) = (v))
#define fs16(p, v) (fv_log((u8 *) (p), 2), *(u16a *) (p) = (v))
#define fs32(p, v) (fv_log((u8 *) (p), 4), *(u32a *) (p) = (v))
#define FMEMCPY(d, s, n) (fv_log((d), (n)), memcpy((d), (s), (n)))
#define FMEMSET(d, v, n) (fv_log((d), (n)), memset((d), (v), (n)))

static void fv_dump(const char *what, CPUI386 *c, uword eip)
{
	fprintf(stderr, "  %s: eip %08x eax %08x ecx %08x edx %08x ebx %08x esp %08x ebp %08x esi %08x edi %08x fl %08x"
		" cs %04x ds %04x es %04x ss %04x fs %04x gs %04x\n", what, eip, c->gprx[0].r32,
		c->gprx[1].r32, c->gprx[2].r32, c->gprx[3].r32, c->gprx[4].r32, c->gprx[5].r32, c->gprx[6].r32,
		c->gprx[7].r32, c->flags, c->seg[SEG_CS].sel, c->seg[SEG_DS].sel, c->seg[SEG_ES].sel, c->seg[SEG_SS].sel,
		c->seg[SEG_FS].sel, c->seg[SEG_GS].sel);
	fprintf(stderr, "           cc op %d dst %08x dst2 %08x src1 %08x src2 %08x mask %04x\n", c->cc.op, c->cc.dst,
		c->cc.dst2, c->cc.src1, c->cc.src2, c->cc.mask);
}

/* after an instruction (fast_eip: the next one): redo it with cpu_exec1 and compare; returns its result */
static bool fv_check(CPUI386 *cpu, uword fast_eip)
{
	CPUI386 f = *cpu;
	// a task switch wrote TSSs with stores not logged: can't be redone, keep it
	if (f.seg[SEG_TR].sel != fv_snap.seg[SEG_TR].sel) {
		fv_count++;
		return true;
	}
	int newn = 0;
	for (int i = 0; i < fv_n; i++) {
		memcpy(fv_new + newn, fv_log_e[i].p, fv_log_e[i].len);
		newn += fv_log_e[i].len;
	}
	for (int i = fv_n - 1; i >= 0; i--)
		memcpy(fv_log_e[i].p, fv_old + fv_log_e[i].off, fv_log_e[i].len);
	*cpu = fv_snap;
	cpu->next_ip = fv_ins;
	cpu->ifetch.paddr = 0;
	bool ok = cpu_exec1(cpu, 1);
	cpu->ifetch.paddr = 0;
	if ((++fv_count & 0x3ffffff) == 0)   // totals every 64M
		fprintf(stderr, "fast verify: %ld instructions checked, %ld differ\n", fv_count, fv_bad);

	const char *diff = NULL;
	if (!ok) diff = "tiny386 raised an exception";
	for (int i = 0; i < 8 && !diff; i++)
		if (f.gprx[i].r32 != cpu->gprx[i].r32) diff = "register";
	if (!diff && fast_eip != cpu->next_ip) {
		// tiny386 runs a JZ/JNZ after CMP/TEST with it
		uword lin = fv_snap.seg[SEG_CS].base + fast_eip;
		u8 q[2];
		bool have = true;
		for (int i = 0; i < 2 && have; i++) {   // through the page tables
			OptAddr a;
			uword pa = lin + i;
			if (cpu->cr0 & CR0_PG) {
				have = translate_laddr(cpu, &a, 1, lin + i, 1, 0);
				pa = a.addr1;
			}
			have = have && pa < (uword) cpu->phys_mem_size;
			if (have) q[i] = cpu->phys_mem[pa];
		}
		if (!(have && (q[0] & ~1) == 0x74 &&
		      cpu->next_ip == ((fast_eip + 2 + (s8) q[1]) & (cpu->code16 ? 0xffff : 0xffffffff))))
			diff = "eip";
	}
	if (!diff) {
		CPUI386 a = f, b = *cpu;
		refresh_flags(&a);
		refresh_flags(&b);
		if (a.flags != b.flags) diff = "flags";
	}
	for (int i = 0; i < 6 && !diff; i++)
		if (f.seg[i].sel != cpu->seg[i].sel || f.seg[i].base != cpu->seg[i].base ||
		    f.seg[i].limit != cpu->seg[i].limit || f.seg[i].flags != cpu->seg[i].flags)
			diff = "segment";
	if (!diff && (f.cpl != cpu->cpl || f.code16 != cpu->code16 || f.sp_mask != cpu->sp_mask || f.halt != cpu->halt ||
		      f.cr0 != cpu->cr0))
		diff = "mode";
	newn = 0;
	for (int i = 0; i < fv_n && !diff; i++) {
		if (memcmp(fv_new + newn, fv_log_e[i].p, fv_log_e[i].len)) diff = "memory";
		newn += fv_log_e[i].len;
	}
	if (diff && fv_bad++ < 20) {
		uword lin = fv_snap.seg[SEG_CS].base + fv_ins;
		fprintf(stderr, "fast verify: %s differs at %04x:%08x (instruction %ld):", diff, fv_snap.seg[SEG_CS].sel,
			fv_ins, fv_count);
		for (int i = 0; i < 12; i++) {   // through the page tables
			OptAddr a;
			uword pa = lin + i;
			if ((cpu->cr0 & CR0_PG) && !translate_laddr(cpu, &a, 1, lin + i, 1, 0)) pa = (uword) -1;
			else if (cpu->cr0 & CR0_PG) pa = a.addr1;
			fprintf(stderr, " %02x", pa < (uword) cpu->phys_mem_size ? cpu->phys_mem[pa] : 0xff);
		}
		fprintf(stderr, "\n");
		fv_dump("before ", &fv_snap, fv_ins);
		fv_dump("fast   ", &f, fast_eip);
		fv_dump("tiny386", cpu, cpu->next_ip);
	}
	return ok;
}

#define FV_BEGIN do { fv_active = true; fv_snap = *cpu; fv_ins = EIP_OF(ins); fv_n = fv_oldn = 0; } while (0)
#define FV_SKIP (fv_active = false)
/* continue from tiny386's result */
#define FV_END(fast_eip) do { \
		if (fv_active) { \
			fv_active = false; \
			if (!fv_check(cpu, (fast_eip))) return false; \
			eip = cpu->next_ip; \
			if (cpu->halt || (cpu->flags & VM) || (cpu->intr && (cpu->flags & IF)) || --steps < 0) \
				goto out_ip; \
			goto reload; \
		} \
	} while (0)
