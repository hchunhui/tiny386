#ifndef I8259_H
#define I8259_H
#include <stdint.h>

typedef struct PicState2 PicState2;
PicState2 *i8259_init(void (*raise_fn)(void *, PicState2 *), void *obj);
int i8259_read_irq(PicState2 *s);
uint32_t i8259_ioport_read(PicState2 *s, uint32_t addr1);
void i8259_ioport_write(PicState2 *s, uint32_t addr, uint32_t val);
int i8259_read_irq(PicState2 *s);
void i8259_set_irq(PicState2 *s, int irq, int level);

#endif /* I8259_H */
