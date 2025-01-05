#ifndef KVM_H
#define KVM_H

struct kvm_run;

typedef struct {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	struct kvm_run *kvm_run;
	int kvm_run_size;

	char *phys_mem;
	long phys_mem_size;
	long cycle;

	bool intr;
	void *pic;
	int (*pic_read_irq)(void *);

	void *io;
	u8 (*io_read8)(void *, int);
	void (*io_write8)(void *, int, u8);
	u16 (*io_read16)(void *, int);
	void (*io_write16)(void *, int, u16);
	u32 (*io_read32)(void *, int);
	void (*io_write32)(void *, int, u32);

	void *iomem;
	u8 (*iomem_read8)(void *, uword);
	void (*iomem_write8)(void *, uword, u8);
	u16 (*iomem_read16)(void *, uword);
	void (*iomem_write16)(void *, uword, u16);
	u32 (*iomem_read32)(void *, uword);
	void (*iomem_write32)(void *, uword, u32);
} CPUKVM;

CPUKVM *cpukvm_new(char *phys_mem, long phys_mem_size);
void cpukvm_step(CPUKVM *cpu, int stepcount);
#endif /* KVM_H */
