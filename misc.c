#include "misc.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#if !defined(_WIN32) && !defined(__wasm__)
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#endif
#ifdef BUILD_ESP32
#include "driver/uart.h"
#endif

#if !defined(_WIN32) && !defined(__wasm__)
static void CtrlC(int _)
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
#ifndef BUILD_ESP32
	atexit(ResetKeyboardInput);
	signal(SIGINT, CtrlC);
#endif

	struct termios term;
	tcgetattr(0, &term);
	term.c_lflag &= ~(ICANON | ECHO | ISIG); // Disable echo as well
	tcsetattr(0, TCSANOW, &term);
}

static int ReadKBByte()
{
#ifdef BUILD_ESP32
	char data;
	if (uart_read_bytes(0, &data, 1, 20 / portTICK_PERIOD_MS) > 0) {
		return data;
	}
	return -1;
#else
	char rxchar = 0;
	int rread = read(fileno(stdin), (char*)&rxchar, 1);
	if( rread > 0 ) // Tricky: getchar can't be used with arrow keys.
		return rxchar;
	else
		abort();
#endif
}

static int IsKBHit()
{
#ifdef BUILD_ESP32
	size_t len;
	if (uart_get_buffered_data_len(0, &len) == ESP_OK) {
		if (len)
			return 1;
	}
	return 0;
#else
	int byteswaiting;
	ioctl(0, FIONREAD, &byteswaiting);
	return !!byteswaiting;
#endif
}
#endif

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

static void cmos_update_time(CMOS *s)
{
	struct tm tm;
	time_t ti;

	ti = time(NULL);
#ifndef _WIN32
	gmtime_r(&ti, &tm);
#else
	gmtime_s(&tm, &ti);
#endif
	s->data[0] = bin2bcd(tm.tm_sec);
	s->data[2] = bin2bcd(tm.tm_min);
	s->data[4] = bin2bcd(tm.tm_hour);
	s->data[6] = bin2bcd(tm.tm_wday);
	s->data[7] = bin2bcd(tm.tm_mday);
	s->data[8] = bin2bcd(tm.tm_mon + 1);
	s->data[9] = bin2bcd(tm.tm_year % 100);
	s->data[0x32] = bin2bcd((tm.tm_year / 100) + 19);
}

CMOS *cmos_init(long mem_size, int irq, void *pic, void (*set_irq)(void *pic, int irq, int level))
{
	CMOS *c = malloc(sizeof(CMOS));
	memset(c, 0, sizeof(CMOS));
	c->irq = irq;
	c->pic = pic;
	c->set_irq = set_irq;

	cmos_update_time(c);
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
#ifndef __wasm__
			ssize_t r;
			do {
				r = write(uart->out_fd, &val, 1);
			} while (r == -1 && errno == EINTR);
#else
			putchar(val);
#endif
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
#if !defined(_WIN32) && !defined(__wasm__)
	if (IsKBHit()) {
		if (!(uart->ioready & 1)) {
			uart->in = ReadKBByte();
			uart->ioready |= 1;
			u8250_update_interrupts(uart);
		}
	}
#endif
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
	cmos_update_time(cmos);
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

uint8_t cmos_set(void *cmos, int addr, uint8_t val)
{
	CMOS *s = cmos;
	if (addr < 128)
		s->data[addr] = val;
	return val;
}

struct fdfmt {
	uint8_t sectors;
	uint8_t tracks;
	uint8_t heads;
};

static const struct fdfmt fmt[] = {
	/* 1.44 MB 3.5 */
	{ 18, 80, 2 }, /* 3.5 2880 */
	{ 20, 80, 2 }, /* 3.5 3200 */
	{ 21, 80, 2 },
	{ 21, 82, 2 },
	{ 21, 83, 2 },
	{ 22, 80, 2 },
	{ 23, 80, 2 },
	{ 24, 80, 2 },
	/* 2.88 MB 3.5 */
	{ 36, 80, 2 },
	{ 39, 80, 2 },
	{ 40, 80, 2 },
	{ 44, 80, 2 },
	{ 48, 80, 2 },
	/* 720 KB 3.5 */
	{  9, 80, 2 }, /* 3.5 1440 */
	{ 10, 80, 2 },
	{ 10, 82, 2 },
	{ 10, 83, 2 },
	{ 13, 80, 2 },
	{ 14, 80, 2 },
	/* 1.2 MB 5.25 */
	{ 15, 80, 2 },
	{ 18, 80, 2 }, /* 5.25 2880 */
	{ 18, 82, 2 },
	{ 18, 83, 2 },
	{ 20, 80, 2 }, /* 5.25 3200 */
	/* 720 KB 5.25 */
	{  9, 80, 2 }, /* 5.25 1440 */
	{ 11, 80, 2 },
	/* 360 KB 5.25 */
	{  9, 40, 2 },
	{  9, 40, 1 },
	{ 10, 41, 2 },
	{ 10, 42, 2 },
	/* 320 KB 5.25 */
	{  8, 40, 2 },
	{  8, 40, 1 },
	{  0,  0, 0 },
};

struct EMULINK {
	uint32_t status;
	uint32_t cmd;
	uint32_t args[4];
	int argi;
	int dataleft;

	// fake floppy drive
	FILE *fdd[2];
	int fdfmti[2];
};

EMULINK *emulink_init()
{
	EMULINK *e = malloc(sizeof(EMULINK));
	memset(e, 0, sizeof(EMULINK));
	e->cmd = -1;
	return e;
}

int emulink_attach_floppy(EMULINK *e, int i, const char *filename)
{
	if (i >= 0 && i < 2) {
		if (e->fdd[i]) {
			fclose(e->fdd[i]);
			e->fdd[i] = NULL;
		}
		if (filename)
			e->fdd[i] = fopen(filename, "r+b");
		if (!e->fdd[i])
			return -1;
		fseek(e->fdd[i], 0, SEEK_END);
		int size = ftell(e->fdd[i]);
		for (int j = 0; fmt[j].sectors; j++) {
			if (size ==
			    fmt[j].sectors * fmt[j].tracks * fmt[j].heads * 512) {
				e->fdfmti[i] = j;
				return 0;
			}
		}
		return -1;
	}
	return 0;
}

uint32_t emulink_status_read(void *s)
{
	EMULINK *e = s;
	return e->status;
}

static void exec_cmd(EMULINK *e)
{
	switch (e->cmd) {
	case 0:
		e->status = 0xaa55ff00;
		e->cmd = -1;
		break;
	case 0x100:
		e->status = 0;
		if (e->fdd[0])
			e->status |= 0x40;
		if (e->fdd[1])
			e->status |= 0x04;
		e->cmd = -1;
		break;
	case 0x101:
	case 0x102:
		if (e->argi == 3) {
			int ret;
			if (!e->fdd[e->args[0]]) {
				e->status = -EIO;
				e->cmd = -1;
				break;
			}
			if (e->args[0] < 2) {
				int c = e->args[1] >> 16;
				int h = (e->args[1] >> 8) & 0xff;
				int s = e->args[1] & 0xff;
				const struct fdfmt *f = &(fmt[e->fdfmti[e->args[0]]]);
				int lba = (c * f->heads + h) * f->sectors + (s - 1);
				ret = fseek(e->fdd[e->args[0]], 512 * lba, SEEK_SET);
				if (ret < 0) {
					e->status = -errno;
					e->cmd = -1;
				} else {
					e->status = 0;
					e->dataleft = 512 * e->args[2];
				}
			}
		}
		break;
	case -1:
		break;
	}
}

void emulink_cmd_write(void *s, uint32_t val)
{
	EMULINK *e = s;
	e->cmd = val;
	e->argi = 0;
	exec_cmd(e);
}

void emulink_data_write(void *s, uint32_t val)
{
	EMULINK *e = s;
	if (e->argi < 4) {
		e->args[e->argi++] = val;
	}
	exec_cmd(e);
}

int emulink_data_write_string(void *s, uint8_t *buf, int size, int count)
{
	EMULINK *e = s;
	switch (e->cmd) {
	case 0x102: // floppy write
		if (!e->fdd[e->args[0]])
			break;
		if (e->argi == 3) {
			int len = size * count;
			if (len > e->dataleft)
				break;
			int ret = fwrite(buf, 1, len, e->fdd[e->args[0]]);
			if (ret != len)
				break;
			e->dataleft -= len;
			if (e->dataleft == 0) {
				e->cmd = -1;
				e->status = 0;
				return count;
			}
			return count;
		}
		break;
	}
	e->cmd = -1;
	e->status = -1;
	return count;
}

int emulink_data_read_string(void *s, uint8_t *buf, int size, int count)
{
	EMULINK *e = s;
	switch (e->cmd) {
	case 0x101: // floppy read
		if (!e->fdd[e->args[0]])
			break;
		if (e->argi == 3) {
			int len = size * count;
			if (len > e->dataleft)
				break;
			int ret = fread(buf, 1, len, e->fdd[e->args[0]]);
			if (ret != len)
				break;
			e->dataleft -= len;
			if (e->dataleft == 0) {
				e->cmd = -1;
				e->status = 0;
				return count;
			}
			return count;
		}
		break;
	}
	e->cmd = -1;
	e->status = -1;
	return count;
}
