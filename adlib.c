/*
 * QEMU Proxy for OPL2/3 emulation by MAME team
 *
 * Copyright (c) 2004-2005 Vassili Karpov (malc)
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "adlib.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

//#define DEBUG

#define ADLIB_KILL_TIMERS 1

#define ADLIB_DESC "Yamaha YM3812 (OPL2)"

#ifdef DEBUG
#include "qemu/timer.h"
#endif

#ifdef DEBUG
#define ldebug(...) dolog (__VA_ARGS__)
#else
#define ldebug(...)
#endif

#include "fmopl.h"
#define SHIFT 1

struct AdlibState {
    uint32_t freq;
    uint32_t port;
    int ticking[2];
    int enabled;
    int active;
#ifdef DEBUG
    int64_t exp[2];
#endif
    void *voice;
    FM_OPL *opl;
};

static void adlib_stop_opl_timer (AdlibState *s, size_t n)
{
    OPLTimerOver (s->opl, n);
    s->ticking[n] = 0;
}

static void adlib_kill_timers (AdlibState *s)
{
    size_t i;

    for (i = 0; i < 2; ++i) {
        if (s->ticking[i]) {
            adlib_stop_opl_timer (s, i);
        }
    }
}

void adlib_write(void *opaque, uint32_t nport, uint32_t val)
{
    AdlibState *s = opaque;
    int a = nport & 3;

    s->active = 1;
//    AUD_set_active_out (s->voice, 1);

    adlib_kill_timers (s);

    OPLWrite (s->opl, a, val);
}

uint32_t adlib_read(void *opaque, uint32_t nport)
{
    AdlibState *s = opaque;
    int a = nport & 3;

    adlib_kill_timers (s);
    return OPLRead (s->opl, a);
}

static void timer_handler (void *opaque, int c, FLOAT interval_Sec)
{
    AdlibState *s = opaque;
    unsigned n = c & 1;
#ifdef DEBUG
    double interval;
    int64_t exp;
#endif

    if (interval_Sec == 0.0) {
        s->ticking[n] = 0;
        return;
    }

    s->ticking[n] = 1;
#ifdef DEBUG
    interval = NANOSECONDS_PER_SECOND * interval_Sec;
    exp = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + interval;
    s->exp[n] = exp;
#endif

//    AUD_init_time_stamp_out (s->voice, &s->ats);
}

void adlib_callback (void *opaque, uint8_t *stream, int free)
{
    AdlibState *s = opaque;
    int samples;

    samples = free >> SHIFT;
    if (!(s->active && s->enabled) || !samples) {
        return;
    }
    YM3812UpdateOne (s->opl, (void *) stream, samples);
}

void adlib_free(AdlibState *s)
{
    if (s->opl) {
        OPLDestroy (s->opl);
        s->opl = NULL;
    }

    s->active = 0;
    s->enabled = 0;
    free(s);
}

AdlibState *adlib_new()
{
    AdlibState *s = malloc(sizeof(AdlibState));
    memset(s, 0, sizeof(AdlibState));
    s->freq = 44100;
    s->opl = OPLCreate (3579545, s->freq);
    if (!s->opl) {
        return NULL;
    }
    else {
        OPLSetTimerHandler(s->opl, timer_handler, s);
        s->enabled = 1;
    }
    return s;
}
