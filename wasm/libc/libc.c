#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>

int errno;

extern unsigned char __heap_base;

static unsigned char *bump = &__heap_base;
void *malloc(unsigned long size)
{
	unsigned char *p = bump;
	bump += (size + 15) / 16 * 16;
	return p;
}

void free(void *p)
{
}

void *calloc(size_t nmemb, size_t size)
{
	void *p = malloc(nmemb * size);
	memset(p, 0, nmemb * size);
	return p;
}

int isdigit(int x)
{
	return (x>='0' && x<='9');
}

int isxdigit(int x)
{
	return ((x>='0' && x<='9') || (x>='a' && x<='f') || (x>='A' && x<='F'));
}

int islower(int x)
{
	return (x>='a' && x<='z');
}

int isspace(int x)
{
	return (x==' ') || (x=='\n') || (x=='\r');
}

int isalpha(int x)
{
	return (x>='a' && x<='z') || (x>='A' && x<='Z');
}

int isupper(int x)
{
	return (x>='A' && x<='Z');
}

int toupper(int x)
{
	return (x>='a' && x<='z')?(x-'a'+'A'):x;
}

void *memset(void *s, int c, unsigned long n)
{
	unsigned char *p = s;
	for (unsigned long i = 0; i != n; i++) {
		p[i] = c;
	}
	return s;
}

void *memcpy(void *dest, const void *src, unsigned long n)
{
	unsigned char *q = dest;
	const unsigned char *p = src;
	for (unsigned long i = 0; i != n; i++)
		q[i] = p[i];
	return dest;
}

char *strcpy(char *dest, const char *src)
{
	char *q = dest;
	const char *p = src;
	unsigned long i;
	for (i = 0; p[i]; i++)
		q[i] = p[i];
	q[i] = p[i];
	return dest;
}

size_t strlen(const char *s)
{
	size_t count = 0;
	while (*s++) count++;
	return count;
}

int strcmp(const char *s1, const char *s2)
{
	for (; *s1 && *s2; s1++, s2++) {
		if (*s1 != *s2)
			break;
	}
	return *s1 - *s2;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = s1;
	const unsigned char *p2 = s2;
	for (size_t i = 0; i != n; i++, p1++, p2++) {
		if (*p1 != *p2)
			return *p1 - *p2;
	}
	return 0;
}

char *strchr(const char *s, int c)
{
	for (; *s; s++) {
		if (*s == c)
			return (char *) s;
	}
	if (*s == c)
		return (char *) s;
	return NULL;
}

char *strdup(const char *s)
{
	size_t len = strlen(s);
	char *p = malloc(len + 1);
	memcpy(p, s, len + 1);
	return p;
}

extern double __get_mticks(void);
int usleep(int usec)
{
	return 0;
}

int clock_gettime(int clockid, struct timespec *tp)
{
	long long v = __get_mticks();
	tp->tv_sec = v / 1000;
	tp->tv_nsec = (v % 1000) * 1000000;
	return 0;
}

time_t time(time_t *tloc)
{
	long long v = __get_mticks();
	v = v / 1000;
	if (tloc)
		*tloc = v;
	return v;
}

static FILE __console;
FILE *stdout = &__console;
FILE *stderr = &__console;

// Compile nanoprintf in this translation unit.
#define NANOPRINTF_IMPLEMENTATION
#include "nanoprintf.h"

void __console_print(const char *ptr);

int putchar(int c)
{
	char buf[2] = {c, 0};
	__console_print(buf);
	return c;
}

int fputc(int c, FILE *fp)
{
	if (fp != &__console)
		abort();
	return putchar(c);
}

int vprintf(const char *fmt, va_list args)
{
	char buffer[512] = {0};
	int rv = npf_vsnprintf(buffer, 511, fmt, args);
	__console_print(buffer);
	return rv;
}

int printf(const char *fmt, ...)
{
	va_list val;
	va_start(val, fmt);
	int rv = vprintf(fmt, val);
	va_end(val);
	return rv;
}

int vfprintf(FILE *fp, const char *fmt, va_list args)
{
	if (fp != &__console) {
		abort();
	}
	return vprintf(fmt, args);
}

int fprintf(FILE *fp, const char *fmt, ...)
{
	va_list val;
	va_start(val, fmt);
	int rv = vfprintf(fp, fmt, val);
	va_end(val);
	return rv;
}

int fflush(FILE *fp)
{
	return 0;
}

int __open(const char *path);
int __read(int fd, void *ptr, double off, double len);
int __write(int fd, const void *ptr, double off, double len);
void __close(int fd);
double __open_get_size(const char *path);

FILE *fopen(const char *path, const char *mode)
{
	int64_t res = __open_get_size(path);
	if (res == -1)
		return NULL;
	FILE *fp = malloc(sizeof(FILE));
	memset(fp, 0, sizeof(FILE));
	fp->fd = __open(path);
	if (fp->fd < 0)
		abort();
	fp->size = res;
	return fp;
}

void rewind(FILE *fp)
{
	fp->i = 0;
}

off_t ftell(FILE *fp)
{
	return fp->i;
}

int fseek(FILE *fp, off_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		fp->i = offset;
		break;
	case SEEK_CUR:
		fp->i += offset;
		break;
	case SEEK_END:
		fp->i = fp->size - offset;
		break;
	}
	return 0;
}

int fclose(FILE *fp)
{
	if (fp == &__console)
		return 0;
	__close(fp->fd);
	fp->fd = -1;
	free(fp);
	return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *fp)
{
	if (fp == &__console)
		abort();
	size_t len = size * nmemb;
	if (fp->i >= fp->size || fp->i + len > fp->size)
		abort();
	if (__read(fp->fd, ptr, fp->i, len) < 0)
		abort();
	fp->i += len;
	return nmemb;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp)
{
	if (fp == &__console)
		abort();
	size_t len = size * nmemb;
	if (fp->i >= fp->size || fp->i + len > fp->size)
		abort();
	if (__write(fp->fd, ptr, fp->i, len) < 0)
		abort();
	fp->i += len;
	return nmemb;
}

char *fgets(char *s, int size, FILE *fp)
{
	memset(s, 0, size);
	if (size == 0 || size == 1)
		return NULL;
	for (int i = 0; i < size - 1; i++, fp->i++) {
		if (fp->i >= fp->size) {
			if (i == 0)
				return NULL;
			return s;
		}
		if (__read(fp->fd, s + i, fp->i, 1) < 0)
			abort();
		if (s[i] == '\n') {
			fp->i++;
			return s;
		}
	}
	return s;
}

void perror(const char *s)
{
	printf("%s: internal error\n", s);
}

// the following are taken from musl libc

static uint64_t seed;

void srand(unsigned s)
{
	seed = s-1;
}

int rand(void)
{
	seed = 6364136223846793005ULL*seed + 1;
	return seed>>33;
}

int atoi(const char *s)
{
	int n=0, neg=0;
	while (isspace(*s)) s++;
	switch (*s) {
	case '-': neg=1;
	case '+': s++;
	}
	/* Compute n as a negative number to avoid overflow on INT_MIN */
	while (isdigit(*s))
		n = 10*n - (*s++ - '0');
	return neg ? n : -n;
}

/* 2000-03-01 (mod 400 year, immediately after feb29 */
#define LEAPOCH (946684800LL + 86400*(31+29))

#define DAYS_PER_400Y (365*400 + 97)
#define DAYS_PER_100Y (365*100 + 24)
#define DAYS_PER_4Y   (365*4   + 1)

static int __secs_to_tm(long long t, struct tm *tm)
{
	long long days, secs, years;
	int remdays, remsecs, remyears;
	int qc_cycles, c_cycles, q_cycles;
	int months;
	int wday, yday, leap;
	static const char days_in_month[] = {31,30,31,30,31,31,30,31,30,31,31,29};

	/* Reject time_t values whose year would overflow int */
//	if (t < INT_MIN * 31622400LL || t > INT_MAX * 31622400LL)
//		return -1;

	secs = t - LEAPOCH;
	days = secs / 86400;
	remsecs = secs % 86400;
	if (remsecs < 0) {
		remsecs += 86400;
		days--;
	}

	wday = (3+days)%7;
	if (wday < 0) wday += 7;

	qc_cycles = days / DAYS_PER_400Y;
	remdays = days % DAYS_PER_400Y;
	if (remdays < 0) {
		remdays += DAYS_PER_400Y;
		qc_cycles--;
	}

	c_cycles = remdays / DAYS_PER_100Y;
	if (c_cycles == 4) c_cycles--;
	remdays -= c_cycles * DAYS_PER_100Y;

	q_cycles = remdays / DAYS_PER_4Y;
	if (q_cycles == 25) q_cycles--;
	remdays -= q_cycles * DAYS_PER_4Y;

	remyears = remdays / 365;
	if (remyears == 4) remyears--;
	remdays -= remyears * 365;

	leap = !remyears && (q_cycles || !c_cycles);
	yday = remdays + 31 + 28 + leap;
	if (yday >= 365+leap) yday -= 365+leap;

	years = remyears + 4*q_cycles + 100*c_cycles + 400LL*qc_cycles;

	for (months=0; days_in_month[months] <= remdays; months++)
		remdays -= days_in_month[months];

	if (months >= 10) {
		months -= 12;
		years++;
	}

	if (years+100 > INT_MAX || years+100 < INT_MIN)
		return -1;

	tm->tm_year = years + 100;
	tm->tm_mon = months + 2;
	tm->tm_mday = remdays + 1;
	tm->tm_wday = wday;
	tm->tm_yday = yday;

	tm->tm_hour = remsecs / 3600;
	tm->tm_min = remsecs / 60 % 60;
	tm->tm_sec = remsecs % 60;

	return 0;
}

struct tm *gmtime_r (const time_t *t, struct tm *tm)
{
	if (__secs_to_tm(*t, tm) < 0) {
		errno = EOVERFLOW;
		return 0;
	}
	tm->tm_isdst = 0;
	return tm;
}

double frexp(double x, int *e)
{
	union { double d; uint64_t i; } y = { x };
	int ee = y.i>>52 & 0x7ff;

	if (!ee) {
		if (x) {
			x = frexp(x*0x1p64, e);
			*e -= 64;
		} else *e = 0;
		return x;
	} else if (ee == 0x7ff) {
		return x;
	}

	*e = ee - 0x3fe;
	y.i &= 0x800fffffffffffffull;
	y.i |= 0x3fe0000000000000ull;
	return y.d;
}
