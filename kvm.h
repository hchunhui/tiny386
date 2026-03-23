#ifndef KVM_H
#define KVM_H

#include "i386.h"
typedef struct CPUKVM CPUKVM;

CPUKVM *cpukvm_new(char *phys_mem, long phys_mem_size, CPU_CB **cb);
void cpukvm_reset(CPUKVM *cpu);
void cpukvm_reset_pm(CPUKVM *cpu, uint32_t start_addr);
void cpukvm_set_gpr(CPUKVM *cpu, int i, u32 val);
void cpukvm_step(CPUKVM *cpu, int stepcount);
void cpukvm_raise_irq(CPUKVM *cpu);
long cpukvm_get_cycle(CPUKVM *cpu);
void cpukvm_register_mem(CPUKVM *cpu, int slot, uint32_t addr, uint32_t len,
			 void *ptr);
#endif /* KVM_H */
