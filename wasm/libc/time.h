#ifndef TIME_H
#define TIME_H

struct timespec
{
	long long tv_sec;
	long int tv_nsec;
};

enum {
	CLOCK_MONOTONIC
};

int clock_gettime(int clockid, struct timespec *tp);

typedef long long time_t;
time_t time(time_t *tloc);

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

struct tm *gmtime_r (const time_t *, struct tm *);

#endif /* TIME_H */
