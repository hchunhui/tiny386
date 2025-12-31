/*
 * QEMU 8253/8254 interval timer emulation
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include "i8254.h"
//#define DEBUG_PIT

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

typedef struct PITChannelState {
	uint32_t count; /* can be 65536 */
	uint16_t latched_count;
	uint8_t count_latched;
	uint8_t status_latched;
	uint8_t status;
	uint8_t read_state;
	uint8_t write_state;
	uint8_t write_latch;
	uint8_t rw_mode;
	uint8_t mode;
	uint8_t bcd; /* not supported */
	uint8_t gate; /* timer start */

	uint32_t count_load_time;
	uint32_t last_irq_count;
	int irq;
} PITChannelState;

struct PITState {
	PITChannelState channels[3];
	void *pic;
	void (*set_irq)(void *pic, int irq, int level);
};

uint32_t get_uticks();
static int pit_get_count(PITChannelState *s)
{
	uint32_t d;
	int counter;

	d = ((uint64_t) (get_uticks() - s->count_load_time)) * PIT_FREQ / 1000000;
	switch(s->mode) {
	case 0:
	case 1:
	case 4:
	case 5:
		counter = (s->count - d) & 0xffff;
		break;
	case 3:
		/* XXX: may be incorrect for odd counts */
		counter = s->count - ((2 * d) % s->count);
		break;
	default:
		counter = s->count - (d % s->count);
		break;
	}
	return counter;
}

/* get pit output bit */
static int pit_get_out1(PITChannelState *s, uint32_t current_time)
{
	uint32_t d;
	int out;

	d = ((uint64_t) (current_time - s->count_load_time)) * PIT_FREQ / 1000000;
	switch(s->mode) {
	default:
	case 0:
		out = (d >= s->count);
		break;
	case 1:
		out = (d < s->count);
		break;
	case 2:
		if ((d % s->count) == 0 && d != 0)
			out = 1;
		else
			out = 0;
		break;
	case 3:
		out = (d % s->count) < ((s->count + 1) >> 1);
		break;
	case 4:
	case 5:
		out = (d == s->count);
		break;
	}
	return out;
}

static inline void pit_load_count(PITState *pit, PITChannelState *s, int val)
{
	if (val == 0)
		val = 0x10000;
	s->count_load_time = get_uticks();
	s->last_irq_count = 0;
	s->count = val;
}

/* if already latched, do not latch again */
static void pit_latch_count(PITChannelState *s)
{
	if (!s->count_latched) {
		s->latched_count = pit_get_count(s);
		s->count_latched = s->rw_mode;
	}
}

void i8254_ioport_write(PITState *pit, uint32_t addr, uint32_t val)
{
	int channel, access;
	PITChannelState *s;

	addr &= 3;
	if (addr == 3) {
		channel = val >> 6;
		if (channel == 3) {
			/* read back command */
			for(channel = 0; channel < 3; channel++) {
				s = &pit->channels[channel];
				if (val & (2 << channel)) {
					if (!(val & 0x20)) {
						pit_latch_count(s);
					}
					if (!(val & 0x10) && !s->status_latched) {
						/* status latch */
						/* XXX: add BCD and null count */
						s->status = (pit_get_out1(s, get_uticks()) << 7) |
							(s->rw_mode << 4) |
							(s->mode << 1) |
							s->bcd;
						s->status_latched = 1;
					}
				}
			}
		} else {
			s = &pit->channels[channel];
			access = (val >> 4) & 3;
			if (access == 0) {
				pit_latch_count(s);
			} else {
				s->rw_mode = access;
				s->read_state = access;
				s->write_state = access;

				s->mode = (val >> 1) & 7;
				s->bcd = val & 1;
				/* XXX: update irq timer ? */
			}
		}
	} else {
		s = &pit->channels[addr];
		switch(s->write_state) {
		default:
		case RW_STATE_LSB:
			pit_load_count(pit, s, val);
			break;
		case RW_STATE_MSB:
			pit_load_count(pit, s, val << 8);
			break;
		case RW_STATE_WORD0:
			s->write_latch = val;
			s->write_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			pit_load_count(pit, s, s->write_latch | (val << 8));
			s->write_state = RW_STATE_WORD0;
			break;
		}
	}
}

uint32_t i8254_ioport_read(PITState *pit, uint32_t addr)
{
	int ret, count;
	PITChannelState *s;

	addr &= 3;
	s = &pit->channels[addr];
	if (s->status_latched) {
		s->status_latched = 0;
		ret = s->status;
	} else if (s->count_latched) {
		switch(s->count_latched) {
		default:
		case RW_STATE_LSB:
			ret = s->latched_count & 0xff;
			s->count_latched = 0;
			break;
		case RW_STATE_MSB:
			ret = s->latched_count >> 8;
			s->count_latched = 0;
			break;
		case RW_STATE_WORD0:
			ret = s->latched_count & 0xff;
			s->count_latched = RW_STATE_MSB;
			break;
		}
	} else {
		switch(s->read_state) {
		default:
		case RW_STATE_LSB:
			count = pit_get_count(s);
			ret = count & 0xff;
			break;
		case RW_STATE_MSB:
			count = pit_get_count(s);
			ret = (count >> 8) & 0xff;
			break;
		case RW_STATE_WORD0:
			count = pit_get_count(s);
			ret = count & 0xff;
			s->read_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			count = pit_get_count(s);
			ret = (count >> 8) & 0xff;
			s->read_state = RW_STATE_WORD0;
			break;
		}
	}
	return ret;
}

static void pit_reset(void *opaque)
{
	PITState *pit = opaque;
	PITChannelState *s;
	int i;

	for(i = 0;i < 3; i++) {
		s = &pit->channels[i];
		s->mode = 3;
		s->gate = (i != 2);
		pit_load_count(pit, s, 0);
		s->irq = -1;
	}
}

void i8254_update_irq(PITState *pit)
{
	uint32_t uticks = get_uticks();
	PITChannelState *s = pit->channels;
	uint32_t d = ((uint64_t) (uticks - s->count_load_time)) * PIT_FREQ / 1000000;
	switch(s->mode) {
	case 2:
	case 3:
		if (s->last_irq_count + s->count - d >= 0x80000000) {
			if (s->irq != -1) {
				pit->set_irq(pit->pic, s->irq, 1);
				pit->set_irq(pit->pic, s->irq, 0);
				s->last_irq_count += s->count;
			}
		}
		break;
	default:
		abort();
	}
}

PITState *i8254_init(int irq, void *pic, void (*set_irq)(void *pic, int irq, int level))
{
	PITState *pit = malloc(sizeof(PITState));
	memset(pit, 0, sizeof(PITState));
	pit->pic = pic;
	pit->set_irq = set_irq;

	pit_reset(pit);
	pit->channels[0].irq = irq;
	return pit;
}

int pit_get_out(PITState *pit, int channel)
{
	PITChannelState *s = &pit->channels[channel];
	uint32_t uticks = get_uticks();
	return pit_get_out1(s, uticks);
}

int pit_get_gate(PITState *pit, int channel)
{
	PITChannelState *s = &pit->channels[channel];
	return s->gate;
}

/* val must be 0 or 1 */
void pit_set_gate(PITState *pit, int channel, int val)
{
	PITChannelState *s = &pit->channels[channel];

	switch(s->mode) {
	default:
	case 0:
	case 4:
		/* XXX: just disable/enable counting */
		break;
	case 1:
	case 5:
		if (s->gate < val) {
			/* restart counting on rising edge */
			s->count_load_time = get_uticks();
		}
		break;
	case 2:
	case 3:
		if (s->gate < val) {
			/* restart counting on rising edge */
			s->count_load_time = get_uticks();
		}
		/* XXX: disable/enable counting */
		break;
	}
	s->gate = val;
}

int pit_get_initial_count(PITState *pit, int channel)
{
	PITChannelState *s = &pit->channels[channel];
	return s->count;
}

int pit_get_mode(PITState *pit, int channel)
{
	PITChannelState *s = &pit->channels[channel];
	return s->mode;
}
