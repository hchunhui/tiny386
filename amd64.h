#ifndef AMD64_H
#define AMD64_H

#include <stdbool.h>
#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

typedef u64 uword;
typedef s64 sword;

typedef struct CPUAMD64 CPUAMD64;

typedef struct {
	void *pic;
	int (*pic_read_irq)(void *);

	void *io;
	u8 (*io_read8)(void *, int);
	void (*io_write8)(void *, int, u8);
	u16 (*io_read16)(void *, int);
	void (*io_write16)(void *, int, u16);
	u32 (*io_read32)(void *, int);
	void (*io_write32)(void *, int, u32);
	int (*io_read_string)(void *, int, uint8_t *, int, int);
	int (*io_write_string)(void *, int, uint8_t *, int, int);

	void *iomem;
	u8 (*iomem_read8)(void *, uword);
	void (*iomem_write8)(void *, uword, u8);
	u16 (*iomem_read16)(void *, uword);
	void (*iomem_write16)(void *, uword, u16);
	u32 (*iomem_read32)(void *, uword);
	void (*iomem_write32)(void *, uword, u32);
	u64 (*iomem_read64)(void *, uword);
	void (*iomem_write64)(void *, uword, u64);
	bool (*iomem_write_string)(void *, uword, uint8_t *, int);
} CPU_CB;

CPUAMD64 *cpuamd64_new(int _, char *phys_mem, long phys_mem_size, CPU_CB **cb);
void cpuamd64_delete(CPUAMD64 *cpu);
void cpuamd64_reset(CPUAMD64 *cpu);
void cpuamd64_reset_pm(CPUAMD64 *cpu, uint32_t start_addr);
void cpuamd64_step(CPUAMD64 *cpu, int stepcount);
void cpuamd64_raise_irq(CPUAMD64 *cpu);
void cpuamd64_set_gpr(CPUAMD64 *cpu, int i, u32 val);
long cpuamd64_get_cycle(CPUAMD64 *cpu);
void cpuamd64_set_vendor(CPUAMD64 *cpu, const char *vendor);

bool cpu_load8(CPUAMD64 *cpu, int seg, uword addr, u8 *res);
bool cpu_store8(CPUAMD64 *cpu, int seg, uword addr, u8 val);
bool cpu_load16(CPUAMD64 *cpu, int seg, uword addr, u16 *res);
bool cpu_store16(CPUAMD64 *cpu, int seg, uword addr, u16 val);
bool cpu_load32(CPUAMD64 *cpu, int seg, uword addr, u32 *res);
bool cpu_store32(CPUAMD64 *cpu, int seg, uword addr, u32 val);
void cpu_setax(CPUAMD64 *cpu, u16 ax);
u16 cpu_getax(CPUAMD64 *cpu);
void cpu_setexc(CPUAMD64 *cpu, int excno, uword excerr);
void cpu_setflags(CPUAMD64 *cpu, uword set_mask, uword clear_mask);
uword cpu_getflags(CPUAMD64 *cpu);
void cpu_abort(CPUAMD64 *cpu, int code);

#endif /* AMD64_H */
