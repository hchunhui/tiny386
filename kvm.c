#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

typedef u32 uword;
typedef s32 sword;

#include "kvm.h"

static void sigalrm_handler(int sig)
{
}

static bool in_iomem(uword addr)
{
	return addr >= 0xa0000 && addr < 0xc0000;
}

CPUKVM *cpukvm_new(char *phys_mem, long phys_mem_size)
{
	CPUKVM *cpu = malloc(sizeof(CPUKVM));
	memset(cpu, 0, sizeof(CPUKVM));
	cpu->phys_mem = phys_mem;
	cpu->phys_mem_size = phys_mem_size;

	int ret, i;
	struct sigaction act;
	struct kvm_pit_config pit_config;
	uint64_t base_addr;

	cpu->kvm_fd = open("/dev/kvm", O_RDWR);
	if (cpu->kvm_fd < 0) {
		fprintf(stderr, "KVM not available\n");
		abort();
	}
	ret = ioctl(cpu->kvm_fd, KVM_GET_API_VERSION, 0);
	if (ret < 0) {
		perror("KVM_GET_API_VERSION");
		abort();
	}
	if (ret != 12) {
		fprintf(stderr, "Unsupported KVM version\n");
		close(cpu->kvm_fd);
		cpu->kvm_fd = -1;
		abort();
	}
	cpu->vm_fd = ioctl(cpu->kvm_fd, KVM_CREATE_VM, 0);
	if (cpu->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		abort();
	}

        if (ioctl(cpu->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
                perror("KVM_SET_TSS_ADDR");
		abort();
	}

	//iomem: addr >= 0xa0000 && addr < 0xc0000;
	struct kvm_userspace_memory_region memreg;
	memreg.slot = 0;
	memreg.flags = 0;
	memreg.guest_phys_addr = 0;
	memreg.memory_size = 0xa0000;
	memreg.userspace_addr = (unsigned long) phys_mem;
        if (ioctl(cpu->vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
		abort();
	}

	memreg.slot = 1;
	memreg.flags = 0;
	memreg.guest_phys_addr = 0xc0000;
	memreg.memory_size = phys_mem_size - 0xc0000;
	memreg.userspace_addr = (unsigned long) phys_mem + 0xc0000;
        if (ioctl(cpu->vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
		abort();
	}

	cpu->vcpu_fd = ioctl(cpu->vm_fd, KVM_CREATE_VCPU, 0);
	if (cpu->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
		abort();
	}

	/* map the kvm_run structure */
	cpu->kvm_run_size = ioctl(cpu->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (cpu->kvm_run_size < 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		abort();
	}

	cpu->kvm_run = mmap(NULL, cpu->kvm_run_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, cpu->vcpu_fd, 0);
	if (!cpu->kvm_run) {
		perror("mmap kvm_run");
		abort();
	}

	act.sa_handler = sigalrm_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);


	struct kvm_sregs sregs;
	struct kvm_regs regs;
        if (ioctl(cpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}
	sregs.cs.selector = 0xf000;
	sregs.cs.base = 0xf0000;

        if (ioctl(cpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0xfff0;

	if (ioctl(cpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	return cpu;
}

void cpukvm_step(CPUKVM *cpu, int stepcount)
{
	struct kvm_run *run = cpu->kvm_run;
	struct kvm_interrupt kintr;
	struct itimerval ival;
	int ret;

	if (cpu->intr) {
		if (run->ready_for_interrupt_injection) {
			cpu->intr = false;
			int no = cpu->pic_read_irq(cpu->pic);
//			fprintf(stderr, "kvm: inject %d %x\n", no, no);
			kintr.irq = no;
			ret = ioctl(cpu->vcpu_fd, KVM_INTERRUPT, &kintr);
			if (ret < 0) {
				perror("inject intr");
				abort();
			}
		} else {
			run->request_interrupt_window = 1;
		}
	} else {
		run->request_interrupt_window = 0;
	}

	/* Not efficient but simple: we use a timer to interrupt the
	   execution after a given time */
	ival.it_interval.tv_sec = 0;
	ival.it_interval.tv_usec = 0;
	ival.it_value.tv_sec = 0;
	ival.it_value.tv_usec = 10 * 1000;
	setitimer(ITIMER_REAL, &ival, NULL);

	ret = ioctl(cpu->vcpu_fd, KVM_RUN, 0);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			/* timeout */
			return;
		}
		perror("CPUKVM_RUN");
		abort();
	}
	//	printf("exit=%d\n", run->exit_reason);
	switch(run->exit_reason) {
	case KVM_EXIT_IRQ_WINDOW_OPEN:
		break;
	case KVM_EXIT_HLT:
		usleep(1);
		break;
	case KVM_EXIT_IO: {
		u8 *ptr = (u8 *)run + run->io.data_offset;
		int i;
		for(i = 0; i < run->io.count; i++) {
			if (run->io.direction == KVM_EXIT_IO_OUT) {
				switch(run->io.size) {
				case 1:
					cpu->io_write8(cpu->io, run->io.port, *(u8 *)ptr);
					break;
				case 2:
					cpu->io_write16(cpu->io, run->io.port, *(u16 *)ptr);
					break;
				case 4:
					cpu->io_write32(cpu->io, run->io.port, *(u32 *)ptr);
					break;
				default:
					abort();
				}
			} else {
				switch(run->io.size) {
				case 1:
					*(u8 *)ptr = cpu->io_read8(cpu->io, run->io.port);
					break;
				case 2:
					*(u16 *)ptr =cpu->io_read16(cpu->io, run->io.port);
					break;
				case 4:
					*(u32 *)ptr = cpu->io_read32(cpu->io, run->io.port);
					break;
				default:
					abort();
				}
			}
			ptr += run->io.size;
		}
		break;
	}
	case KVM_EXIT_MMIO: {
		void *data = run->mmio.data;
		uint64_t addr = run->mmio.phys_addr;
		if (!in_iomem(addr))
			break;
		if (run->mmio.is_write) {
			switch(run->mmio.len) {
			case 1:
				cpu->iomem_write8(cpu->iomem, addr, *(u8 *) data);
				break;
			case 2:
				cpu->iomem_write16(cpu->iomem, addr, *(u16 *) data);
				break;
			case 4:
				cpu->iomem_write32(cpu->iomem, addr, *(u32 *) data);
				break;
			default:
				abort();
			}
		} else {
			switch(run->mmio.len) {
			case 1:
				*(u8 *) data = cpu->iomem_read8(cpu->iomem, addr);
				break;
			case 2:
				*(u16 *) data = cpu->iomem_read16(cpu->iomem, addr);
				break;
			case 4:
				*(u32 *) data = cpu->iomem_read32(cpu->iomem, addr);
				break;
			default:
				abort();
			}
		}
		break;
	}
	case KVM_EXIT_FAIL_ENTRY:
		fprintf(stderr, "KVM_EXIT_FAIL_ENTRY: reason=0x%" PRIx64 "\n",
				(uint64_t)run->fail_entry.hardware_entry_failure_reason);
#if 0
		{
			struct kvm_regs regs;
			if (ioctl(s->vcpu_fd, KVM_GET_REGS, &regs) < 0) {
				perror("KVM_SET_REGS");
				exit(1);
			}
			printf("RIP=%016" PRIx64 "\n", (uint64_t)regs.rip);
		}
#endif
		exit(1);
	case KVM_EXIT_INTERNAL_ERROR:
		fprintf(stderr, "KVM_EXIT_INTERNAL_ERROR: suberror=0x%x\n",
				(uint32_t)run->internal.suberror);
		abort();
	default:
		fprintf(stderr, "KVM: unsupported exit_reason=%d\n", run->exit_reason);
		abort();
	}
}
