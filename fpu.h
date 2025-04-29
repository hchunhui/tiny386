#ifndef FPU_H
#define FPU_H

#include <stdbool.h>
#include <stdint.h>

typedef struct FPU FPU;

FPU *fpu_new();
bool fpu_exec1(FPU *fpu, void *cpu, int op, int group, unsigned int i);
bool fpu_exec2(FPU *fpu, void *cpu, bool opsz16, int op, int group, int seg, uint32_t addr);

#endif /* FPU_H */
