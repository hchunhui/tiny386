#ifndef FPU_H
#define FPU_H

#include <stdbool.h>
#include <stdint.h>

typedef struct FPU FPU;

FPU *fpu_new();
void fpu_delete(FPU *fpu);
bool fpu_exec1(FPU *fpu, void *cpu, int op, int group, unsigned int i);
bool fpu_exec2(FPU *fpu, void *cpu, bool opsz16, int op, int group, int seg, uword addr);

/* The decoded memory moves copy a little-endian binary64 value directly. */
#if defined(FAST_PD) && defined(I386_ENABLE_FPU) && !defined(FAST_VERIFY) && !defined(USE_FLOAT80) && \
    defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && \
    (!defined(__FLOAT_WORD_ORDER__) || __FLOAT_WORD_ORDER__ == __ORDER_LITTLE_ENDIAN__) && \
    __SIZEOF_DOUBLE__ == 8 && __DBL_MANT_DIG__ == 53 && __DBL_MAX_EXP__ == 1024
#define PD_X87_ENABLED
void fpu_move_real64(FPU *fpu, int group, void *p);
#endif

#endif /* FPU_H */
