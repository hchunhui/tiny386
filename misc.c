#include "misc.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
static void CtrlC()
{
	exit( 0 );
}

static void ResetKeyboardInput()
{
	// Re-enable echo, etc. on keyboard.
	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag |= ICANON | ECHO;
	tcsetattr(0, TCSANOW, &term);
}

// Override keyboard, so we can capture all keyboard input for the VM.
void CaptureKeyboardInput()
{
	// Hook exit, because we want to re-enable keyboard.
	atexit(ResetKeyboardInput);
	signal(SIGINT, CtrlC);

	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag &= ~(ICANON | ECHO | ISIG); // Disable echo as well
	tcsetattr(0, TCSANOW, &term);
}

static int ReadKBByte()
{
	char rxchar = 0;
	int rread = read(fileno(stdin), (char*)&rxchar, 1);
	if( rread > 0 ) // Tricky: getchar can't be used with arrow keys.
		return rxchar;
	else
		abort();
}

static int IsKBHit()
{
	int byteswaiting;
	ioctl(0, FIONREAD, &byteswaiting);
	return !!byteswaiting;
}

/* sysprog21/semu */
struct U8250 {
	uint8_t dll, dlh;
	uint8_t lcr;
	uint8_t ier;
	uint8_t mcr;
	uint8_t ioready;
	int out_fd;
	uint8_t in;

	int irq;
	void *pic;
	void (*set_irq)(void *pic, int irq, int level);
};

U8250 *u8250_init(int irq, void *pic, void (*set_irq)(void *pic, int irq, int level))
{
	U8250 *s = malloc(sizeof(U8250));
	memset(s, 0, sizeof(U8250));
	s->out_fd = 1;

	s->irq = irq;
	s->pic = pic;
	s->set_irq = set_irq;
	return s;
}

struct CMOS {
	uint8_t data[128];
	int index;
	int irq;
	uint32_t irq_timeout;
	uint32_t irq_period;
	void *pic;
	void (*set_irq)(void *pic, int irq, int level);
};

static int bin2bcd(int a)
{
	return ((a / 10) << 4) | (a % 10);
}

CMOS *cmos_init(long mem_size, int irq, void *pic, void (*set_irq)(void *pic, int irq, int level))
{
	CMOS *c = malloc(sizeof(CMOS));
	memset(c, 0, sizeof(CMOS));
	c->irq = irq;
	c->pic = pic;
	c->set_irq = set_irq;

	struct tm tm;
	time_t ti;

	ti = time(NULL);
	gmtime_r(&ti, &tm);
	c->data[0] = bin2bcd(tm.tm_sec);
	c->data[2] = bin2bcd(tm.tm_min);
	c->data[4] = bin2bcd(tm.tm_hour);
	c->data[6] = bin2bcd(tm.tm_wday);
	c->data[7] = bin2bcd(tm.tm_mday);
	c->data[8] = bin2bcd(tm.tm_mon + 1);
	c->data[9] = bin2bcd(tm.tm_year % 100);
	c->data[0x32] = bin2bcd((tm.tm_year / 100) + 19);
	c->data[10] = 0x26;
	c->data[11] = 0x02;
	c->data[12] = 0x00;
	c->data[13] = 0x80;
	if (mem_size >= 1024 * 1024) {
		if (mem_size >= 64 * 1024 * 1024) {
			mem_size -= 16 * 1024 * 1024;
			c->data[0x35] = mem_size >> 24;
			c->data[0x34] = mem_size >> 16;
		} else {
			mem_size -= 1024 * 1024;
			c->data[0x31] = mem_size >> 18;
			c->data[0x30] = mem_size >> 10;
		}
	}
	return c;
}

static void u8250_update_interrupts(U8250 *uart)
{
	if (uart->ier & uart->ioready) {
		uart->set_irq(uart->pic, uart->irq, 1);
	} else {
		uart->set_irq(uart->pic, uart->irq, 0);
	}
}

uint8_t u8250_reg_read(U8250 *uart, int off)
{
	uint8_t val;
	switch (off) {
	case 0:
		if (uart->lcr & (1 << 7)) { /* DLAB */
			val = uart->dll;
			break;
		}
		val = uart->in;
		uart->ioready &= ~1;
		u8250_update_interrupts(uart);
		break;
	case 1:
		if (uart->lcr & (1 << 7)) { /* DLAB */
			val = uart->dlh;
			break;
		}
		val = uart->ier;
		break;
	case 2:
		val = (uart->ier & uart->ioready) ? 0 : 1;
		break;
	case 3:
		val = uart->lcr;
		break;
	case 4:
		val = uart->mcr;
		break;
	case 5:
		/* LSR = no error, TX done & ready */
		val = 0x60 | (uart->ioready & 1);
		break;
	case 6:
		/* MSR = carrier detect, no ring, data ready, clear to send. */
		val = 0xb0;
		break;
		/* no scratch register, so we should be detected as a plain 8250. */
	default:
		val = 0;
	}
	return val;
}

void u8250_reg_write(U8250 *uart, int off, uint8_t val)
{
	switch (off) {
	case 0:
		if (uart->lcr & (1 << 7)) {
			uart->dll = val;
			break;
		} else {
			ssize_t r;
			do {
				r = write(uart->out_fd, &val, 1);
			} while (r == -1 && errno == EINTR);
		}
		break;
	case 1:
		if (uart->lcr & (1 << 7)) {
			uart->dlh = val;
			break;
		} else {
			uart->ier = val;
			if (uart->ier & 2)
				uart->ioready |= 2;
			else
				uart->ioready &= ~2;
			u8250_update_interrupts(uart);
		}
		break;
	case 3:
		uart->lcr = val;
		break;
	case 4:
		uart->mcr = val;
		break;
	}
}

void u8250_update(U8250 *uart)
{
	if (IsKBHit()) {
		if (!(uart->ioready & 1)) {
			uart->in = ReadKBByte();
			uart->ioready |= 1;
			u8250_update_interrupts(uart);
		}
	}
}

#define CMOS_FREQ 32768
#define RTC_REG_A               10
#define RTC_REG_B               11
#define RTC_REG_C               12
#define RTC_REG_D               13
#define REG_A_UIP 0x80
#define REG_B_SET 0x80
#define REG_B_PIE 0x40
#define REG_B_AIE 0x20
#define REG_B_UIE 0x10

static uint32_t cmos_get_timer(CMOS *s)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec * CMOS_FREQ +
        ((uint64_t)ts.tv_nsec * CMOS_FREQ / 1000000000);
}

static void cmos_update_timer(CMOS *s)
{
    int period_code;

    period_code = s->data[RTC_REG_A] & 0x0f;
    if ((s->data[RTC_REG_B] & REG_B_PIE) &&
        period_code != 0) {
        if (period_code <= 2)
            period_code += 7;
        s->irq_period = 1 << (period_code - 1);
        s->irq_timeout = (cmos_get_timer(s) + s->irq_period) &
            ~(s->irq_period - 1);
    }
}

void cmos_update_irq(CMOS *s)
{
    uint32_t d;
    if (s->data[RTC_REG_B] & REG_B_PIE) {
        d = cmos_get_timer(s) - s->irq_timeout;
        if ((int32_t)d >= 0) {
            /* this is not what the real RTC does. Here we sent the IRQ
               immediately */
            s->data[RTC_REG_C] |= 0xc0;
            s->set_irq(s->pic, s->irq, 1);
	    s->set_irq(s->pic, s->irq, 0);
            /* update for the next irq */
            s->irq_timeout += s->irq_period;
        }
    }
}

uint8_t cmos_ioport_read(CMOS *cmos, int addr)
{
	if (addr == 0x70)
		return 0xff;
	uint8_t val = cmos->data[cmos->index];
	return val;
}

void cmos_ioport_write(CMOS *cmos, int addr, uint8_t val)
{
	if (addr == 0x70)
		cmos->index = val & 0x7f;
	else {
		CMOS *s = cmos;
		switch(s->index) {
		case RTC_REG_A:
			s->data[RTC_REG_A] = (val & ~REG_A_UIP) |
				(s->data[RTC_REG_A] & REG_A_UIP);
			cmos_update_timer(s);
			break;
		case RTC_REG_B:
			s->data[s->index] = val;
			cmos_update_timer(s);
			break;
		default:
			s->data[s->index] = val;
			break;
		}
	}
}
