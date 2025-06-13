#ifndef NE2000_H
#define NE2000_H

#include <stdint.h>

typedef struct NE2000State NE2000State;
void ne2000_ioport_write(void *opaque, uint32_t addr, uint32_t val);
uint32_t ne2000_ioport_read(void *opaque, uint32_t addr);
void ne2000_reset_ioport_write(void *opaque, uint32_t addr, uint32_t val);
uint32_t ne2000_reset_ioport_read(void *opaque, uint32_t addr);
void ne2000_asic_ioport_write(void *opaque, uint32_t addr, uint32_t val);
uint32_t ne2000_asic_ioport_read(void *opaque, uint32_t addr);

void ne2000_step(NE2000State *s);
NE2000State *isa_ne2000_init(int base, int irq,
                             void *pic,
                             void (*set_irq)(void *pic, int irq, int level));

#endif /* NE2000_H */
