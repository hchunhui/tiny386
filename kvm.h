#ifndef KVM_H
#define KVM_H

#include "i386.h"
typedef struct CPUKVM CPUKVM;

CPUKVM *cpukvm_new(char *phys_mem, long phys_mem_size, CPU_CB **cb);
void cpukvm_step(CPUKVM *cpu, int stepcount);
void cpukvm_raise_irq(CPUKVM *cpu);
long cpukvm_get_cycle(CPUKVM *cpu);
#endif /* KVM_H */
