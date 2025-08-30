/*
 * QEMU PC speaker emulation
 *
 * Copyright (c) 2006 Joachim Henke
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

#include "pcspk.h"
#include <stdlib.h>
#include <string.h>

#define PCSPK_BUF_LEN 1792
//#define PCSPK_SAMPLE_RATE 32000
#define PCSPK_SAMPLE_RATE 44100
#define PCSPK_MAX_FREQ (PCSPK_SAMPLE_RATE >> 1)
#define PCSPK_MIN_COUNT ((PIT_FREQ + PCSPK_MAX_FREQ - 1) / PCSPK_MAX_FREQ)

struct PCSpkState {
    uint8_t sample_buf[PCSPK_BUF_LEN];
//    QEMUSoundCard card;
//    SWVoiceOut *voice;
    PITState *pit;
    unsigned int pit_count;
    unsigned int samples;
    unsigned int play_pos;
    int data_on;
    int dummy_refresh_clock;
    int active_out;
};

static inline void generate_samples(PCSpkState *s)
{
    unsigned int i;

    if (s->pit_count) {
        const uint32_t m = PCSPK_SAMPLE_RATE * s->pit_count;
        const uint32_t n = ((uint64_t)PIT_FREQ << 32) / m;

        /* multiple of wavelength for gapless looping */
        s->samples = (PCSPK_BUF_LEN * PIT_FREQ / m * m / (PIT_FREQ >> 1) + 1) >> 1;
        for (i = 0; i < s->samples; ++i)
            s->sample_buf[i] = (64 & (n * i >> 25)) - 32;
    } else {
        s->samples = PCSPK_BUF_LEN;
        for (i = 0; i < PCSPK_BUF_LEN; ++i)
            s->sample_buf[i] = 128; /* silence */
    }
}

#include <stdio.h>

void pcspk_callback(void *opaque, uint8_t *stream, int free)
{
    PCSpkState *s = opaque;
    unsigned int n;

    if (pit_get_mode(s->pit, 2) != 3)
        return;
    if (!s->data_on)
        return;

    n = pit_get_initial_count(s->pit, 2);
    /* avoid frequencies that are not reproducible with sample rate */
    if (n < PCSPK_MIN_COUNT)
        n = 0;

    if (s->pit_count != n) {
        s->pit_count = n;
        s->play_pos = 0;
        generate_samples(s);
    }

    int k = 0;
    while (free > 0) {
        n = s->samples - s->play_pos;
        if (n > free)
            n = free;
        memcpy(stream + k, &s->sample_buf[s->play_pos], n);
//        n = AUD_write(s->voice, &s->sample_buf[s->play_pos], n);
        if (!n)
            break;
        s->play_pos = (s->play_pos + n) % s->samples;
        free -= n;
        k += n;
    }
}

uint32_t pcspk_ioport_read(void *opaque)
{
    PCSpkState *s = opaque;
    int out;

    s->dummy_refresh_clock ^= (1 << 4);
    out = pit_get_out(s->pit, 2) << 5;

    return pit_get_gate(s->pit, 2) | (s->data_on << 1) | s->dummy_refresh_clock | out;
}

static void AUD_set_active_out (PCSpkState *s, int i)
{
    s->active_out = i;
}

void pcspk_ioport_write(void *opaque, uint32_t val)
{
    PCSpkState *s = opaque;
    const int gate = val & 1;
    int oldout = gate & s->data_on;

    s->data_on = (val >> 1) & 1;
    pit_set_gate(s->pit, 2, gate);
    if (gate) /* restart */
        s->play_pos = 0;

    int newout = gate & s->data_on;
    if (oldout != newout) {
        AUD_set_active_out(s, gate & s->data_on);
    }
}

int pcspk_get_active_out(PCSpkState *s)
{
    return s->active_out;
}

PCSpkState *pcspk_init(PITState *pit)
{
    PCSpkState *s = malloc(sizeof(PCSpkState));
    memset(s, 0, sizeof(PCSpkState));

    s->pit = pit;
//    register_ioport_read(0x61, 1, 1, pcspk_ioport_read, s);
//    register_ioport_write(0x61, 1, 1, pcspk_ioport_write, s);
    return s;
}
