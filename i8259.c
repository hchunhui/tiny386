/*
 * QEMU 8259 interrupt controller emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "i8259.h"

typedef struct PicState {
	uint8_t last_irr; /* edge detection */
	uint8_t irr; /* interrupt request register */
	uint8_t imr; /* interrupt mask register */
	uint8_t isr; /* interrupt service register */
	uint8_t priority_add; /* highest irq priority */
	uint8_t irq_base;
	uint8_t read_reg_select;
	uint8_t poll;
	uint8_t special_mask;
	uint8_t init_state;
	uint8_t auto_eoi;
	uint8_t rotate_on_auto_eoi;
	uint8_t special_fully_nested_mode;
	uint8_t init4; /* true if 4 byte init */
	uint8_t single_mode; /* true if slave pic is not initialized */
	PicState2 *pics_state;
} PicState;

struct PicState2 {
	/* 0 is master pic, 1 is slave pic */
	PicState pics[2];
	void (*raise_fn)(void *, PicState2 *);
	void *obj;
};

/* set irq level. If an edge is detected, then the IRR is set to 1 */
static inline void pic_set_irq1(PicState *s, int irq, int level)
{
	int mask;
	mask = 1 << irq;
	/* edge triggered */
	if (level) {
		if ((s->last_irr & mask) == 0)
			s->irr |= mask;
		s->last_irr |= mask;
	} else {
		s->last_irr &= ~mask;
	}
}

/* return the highest priority found in mask (highest = smallest
   number). Return 8 if no irq */
static inline int get_priority(PicState *s, int mask)
{
	int priority;
	if (mask == 0)
		return 8;
	priority = 0;
	while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
		priority++;
	return priority;
}

/* return the pic wanted interrupt. return -1 if none */
static int pic_get_irq(PicState *s)
{
	int mask, cur_priority, priority;

	mask = s->irr & ~s->imr;
	priority = get_priority(s, mask);
	if (priority == 8)
		return -1;
	/* compute current priority. If special fully nested mode on the
	   master, the IRQ coming from the slave is not taken into account
	   for the priority computation. */
	mask = s->isr;
	if (s->special_mask)
		mask &= ~s->imr;
	if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
		mask &= ~(1 << 2);
	cur_priority = get_priority(s, mask);
	if (priority < cur_priority) {
		/* higher priority found: an irq should be generated */
		return (priority + s->priority_add) & 7;
	} else {
		return -1;
	}
}

/* raise irq to CPU if necessary. must be called every time the active
   irq may change */
static void pic_update_irq(PicState2 *s)
{
	int irq2, irq;

	/* first look at slave pic */
	irq2 = pic_get_irq(&s->pics[1]);
	if (irq2 >= 0) {
		/* if irq request by slave pic, signal master PIC */
		pic_set_irq1(&s->pics[0], 2, 1);
		pic_set_irq1(&s->pics[0], 2, 0);
	}
	/* look at requested irq */
	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0) {
		s->raise_fn(s->obj, s);
	}
}

void i8259_set_irq(PicState2 *s, int irq, int level)
{
	pic_set_irq1(&s->pics[irq >> 3], irq & 7, level);
	pic_update_irq(s);
}

/* acknowledge interrupt 'irq' */
static inline void pic_intack(PicState *s, int irq)
{
	if (s->auto_eoi) {
		if (s->rotate_on_auto_eoi)
			s->priority_add = (irq + 1) & 7;
	} else {
		s->isr |= (1 << irq);
	}
	s->irr &= ~(1 << irq);
}

int i8259_read_irq(PicState2 *s)
{
	int irq, irq2, intno;

	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0) {
		pic_intack(&s->pics[0], irq);
		if (irq == 2) {
			irq2 = pic_get_irq(&s->pics[1]);
			if (irq2 >= 0) {
				pic_intack(&s->pics[1], irq2);
			} else {
				/* spurious IRQ on slave controller */
				irq2 = 7;
			}
			intno = s->pics[1].irq_base + irq2;
			irq = irq2 + 8;
		} else {
			intno = s->pics[0].irq_base + irq;
		}
	} else {
		/* spurious IRQ on host controller */
		irq = 7;
		intno = s->pics[0].irq_base + irq;
	}
	pic_update_irq(s);
	return intno;
}

static void pic_reset(PicState *s)
{
	s->last_irr = 0;
	s->irr = 0;
	s->imr = 0;
	s->isr = 0;
	s->priority_add = 0;
	s->irq_base = 0;
	s->read_reg_select = 0;
	s->poll = 0;
	s->special_mask = 0;
	s->init_state = 0;
	s->auto_eoi = 0;
	s->rotate_on_auto_eoi = 0;
	s->special_fully_nested_mode = 0;
	s->init4 = 0;
	s->single_mode = 0;
}

static void hw_error(const char *msg)
{
	abort();
}

static void pic_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
	PicState *s = opaque;
	int priority, cmd, irq;

#ifdef DEBUG_PIC
	printf("pic_write: addr=0x%02x val=0x%02x\n", addr, val);
#endif
	addr &= 1;
	if (addr == 0) {
		if (val & 0x10) {
			/* init */
			pic_reset(s);
			s->init_state = 1;
			s->init4 = val & 1;
			s->single_mode = val & 2;
			if (val & 0x08)
				hw_error("level sensitive irq not supported");
		} else if (val & 0x08) {
			if (val & 0x04)
				s->poll = 1;
			if (val & 0x02)
				s->read_reg_select = val & 1;
			if (val & 0x40)
				s->special_mask = (val >> 5) & 1;
		} else {
			cmd = val >> 5;
			switch(cmd) {
			case 0:
			case 4:
				s->rotate_on_auto_eoi = cmd >> 2;
				break;
			case 1: /* end of interrupt */
			case 5:
				priority = get_priority(s, s->isr);
				if (priority != 8) {
					irq = (priority + s->priority_add) & 7;
					s->isr &= ~(1 << irq);
					if (cmd == 5)
						s->priority_add = (irq + 1) & 7;
					pic_update_irq(s->pics_state);
				}
				break;
			case 3:
				irq = val & 7;
				s->isr &= ~(1 << irq);
				pic_update_irq(s->pics_state);
				break;
			case 6:
				s->priority_add = (val + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			case 7:
				irq = val & 7;
				s->isr &= ~(1 << irq);
				s->priority_add = (irq + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			default:
				/* no operation */
				break;
			}
		}
	} else {
		switch(s->init_state) {
		case 0:
			/* normal mode */
			s->imr = val;
			pic_update_irq(s->pics_state);
			break;
		case 1:
			s->irq_base = val & 0xf8;
			s->init_state = s->single_mode ? (s->init4 ? 3 : 0) : 2;
			break;
		case 2:
			if (s->init4) {
				s->init_state = 3;
			} else {
				s->init_state = 0;
			}
			break;
		case 3:
			s->special_fully_nested_mode = (val >> 4) & 1;
			s->auto_eoi = (val >> 1) & 1;
			s->init_state = 0;
			break;
		}
	}
}

static uint32_t pic_poll_read (PicState *s, uint32_t addr1)
{
	int ret;

	ret = pic_get_irq(s);
	if (ret >= 0) {
		if (addr1 >> 7) {
			s->pics_state->pics[0].isr &= ~(1 << 2);
			s->pics_state->pics[0].irr &= ~(1 << 2);
		}
		s->irr &= ~(1 << ret);
		s->isr &= ~(1 << ret);
		if (addr1 >> 7 || ret != 2)
			pic_update_irq(s->pics_state);
	} else {
		ret = 0x07;
		pic_update_irq(s->pics_state);
	}

	return ret;
}

static uint32_t pic_ioport_read(void *opaque, uint32_t addr1)
{
	PicState *s = opaque;
	unsigned int addr;
	int ret;

	addr = addr1;
	addr &= 1;
	if (s->poll) {
		ret = pic_poll_read(s, addr1);
		s->poll = 0;
	} else {
		if (addr == 0) {
			if (s->read_reg_select)
				ret = s->isr;
			else
				ret = s->irr;
		} else {
			ret = s->imr;
		}
	}
#ifdef DEBUG_PIC
	printf("pic_read: addr=0x%02x val=0x%02x\n", addr1, ret);
#endif
	return ret;
}

uint32_t i8259_ioport_read(PicState2 *s, uint32_t addr)
{
	if (addr == 0x20 || addr == 0x21)
		return pic_ioport_read(&s->pics[0], addr);
	return pic_ioport_read(&s->pics[1], addr);
}

void i8259_ioport_write(PicState2 *s, uint32_t addr, uint32_t val)
{
	if (addr == 0x20 || addr == 0x21)
		return pic_ioport_write(&s->pics[0], addr, val);
	pic_ioport_write(&s->pics[1], addr, val);
}

PicState2 *i8259_init(void (*raise_fn)(void *, PicState2 *s), void *obj)
{
	PicState2 *s = malloc(sizeof(PicState2));
	pic_reset(&s->pics[0]);
	pic_reset(&s->pics[1]);
	s->pics[0].pics_state = s;
	s->pics[1].pics_state = s;
	s->raise_fn = raise_fn;
	s->obj = obj;
	return s;
}
