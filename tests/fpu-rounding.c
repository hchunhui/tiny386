/* cc -O2 -DI386_ENABLE_FPU tests/fpu-rounding.c i386.c -lm -o /tmp/fpu-rounding
   /tmp/fpu-rounding [--stream] */
#include "../fpu.c"
#include <stdio.h>
#include <inttypes.h>

static double run(FPU *fpu, int op, int rc, double a, double b)
{
	fpu->cw = rc << 10;
	if (op == 8) {
		fpset(fpu, 0, a);
		assert(fpu_exec1(fpu, NULL, 1, 7, 2)); /* FSQRT */
	} else {
		fparith(fpu, op, 0, a, b);
	}
	return fpget(fpu, 0);
}
static double bits(uint64_t u) { union union64 v = { .i = u }; return v.f; }
static uint64_t raw(double d) { union union64 v = { .f = d }; return v.i; }

int main(int argc, char **argv)
{
	FPU *fpu = fpu_new();
	if (argc == 2 && strcmp(argv[1], "--stream") == 0) {
		int op, rc;
		uint64_t a, b;
		while (scanf("%d %d %" SCNx64 " %" SCNx64, &op, &rc, &a, &b) == 4)
			printf("%016" PRIx64 "\n", raw(run(fpu, op, rc, bits(a), bits(b))));
		fpu_delete(fpu);
		return 0;
	}
	assert(run(fpu, 0, 2, 1, 0x1p-100) == 0x1.000002p0);
	assert(run(fpu, 0, 0, 0x1.000001p0, 0x1p-54) == 0x1.000002p0);
	for (int rc = 0; rc < 4; rc++) {
		assert(run(fpu, 0, rc, 1, 1) == 2);
		assert(run(fpu, 1, rc, 1.5, 2) == 3);
		assert(run(fpu, 6, rc, 3, 2) == 1.5);
		assert(run(fpu, 8, rc, 4, 0) == 2);
	}
	uint64_t q1 = 0x7ff8000000000001ull, q2 = 0xfff8000000000002ull;
	uint64_t sn = 0x7ff0000000000003ull;
	for (int op = 0; op <= 7; op++) {
		if (op == 2 || op == 3) continue;
		assert(raw(run(fpu, op, 0, bits(q1), bits(q2))) == q2);
		assert(raw(run(fpu, op, 0, bits(q2), bits(q1))) == q2);
		assert(raw(run(fpu, op, 0, bits(sn), bits(q1))) == q1);
		assert(raw(run(fpu, op, 0, bits(q1), bits(sn))) == q1);
		assert(raw(run(fpu, op, 0, bits(sn), bits(sn + 1))) == ((sn + 1) | (1ull << 51)));
		assert(raw(run(fpu, op, 0, bits(q1 | (1ull << 63)), bits(q1))) == q1);
		assert(raw(run(fpu, op, 0, bits(sn), 1)) == (sn | (1ull << 51)));
	}
	assert(raw(run(fpu, 6, 0, 0, 0)) == 0xfff8000000000000ull);
	for (int pc = 2; pc <= 3; pc++) {
		fpu->cw = pc << 8;
		fparith(fpu, 0, 0, 1, 0x1p-30);
		assert(fpget(fpu, 0) == 1 + 0x1p-30);
	}
	fpu_delete(fpu);
	puts("FPU: directed/tie residuals, exact arithmetic, sqrt, and NaN precedence passed");
}
