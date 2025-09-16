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

uint8_t cmos_set(void *cmos, int addr, uint8_t val);

typedef struct EMULINK EMULINK;
EMULINK *emulink_init();

int emulink_attach_floppy(EMULINK *e, int i, const char *filename);
uint32_t emulink_status_read(void *s);
void emulink_cmd_write(void *s, uint32_t val);
void emulink_data_write(void *s, uint32_t val);
int emulink_data_write_string(void *s, uint8_t *buf, int size, int count);
int emulink_data_read_string(void *s, uint8_t *buf, int size, int count);

#endif /* MISC_H */
