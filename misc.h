#ifndef MISC_H
#define MISC_H

#include <stdint.h>

typedef struct U8250 U8250;
U8250 *u8250_init(int irq, void *pic, void (*set_irq)(void *pic, int irq, int level));
uint8_t u8250_reg_read(U8250 *uart, int off);
void u8250_reg_write(U8250 *uart, int off, uint8_t val);
void u8250_update(U8250 *uart);
void CaptureKeyboardInput();

typedef struct CMOS CMOS;
CMOS *cmos_init(long mem_size, int irq, void *pic, void (*set_irq)(void *pic, int irq, int level));
void cmos_update_irq(CMOS *s);
uint8_t cmos_ioport_read(CMOS *cmos, int addr);
void cmos_ioport_write(CMOS *cmos, int addr, uint8_t val);

#endif /* MISC_H */
