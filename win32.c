#ifdef _WIN32
#include <time.h>

/**
 * implementation of clock_gettime(CLOCK_MONOTONIC, tv) from unistd.h for Windows
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#define MS_PER_SEC 1000ULL // MS = milliseconds
#define US_PER_MS 1000ULL  // US = microseconds
#define HNS_PER_US 10ULL   // HNS = hundred-nanoseconds (e.g., 1 hns = 100 ns)
#define NS_PER_US 1000ULL

#define HNS_PER_SEC (MS_PER_SEC * US_PER_MS * HNS_PER_US)
#define NS_PER_HNS (100ULL) // NS = nanoseconds
#define NS_PER_SEC (MS_PER_SEC * US_PER_MS * NS_PER_US)

// https://stackoverflow.com/questions/5404277/porting-clock-gettime-to-windows
static void clock_gettime_monotonic(struct timespec *tv)
{
	static LARGE_INTEGER ticksPerSec;
	LARGE_INTEGER ticks;

	if (!ticksPerSec.QuadPart)
	{
		QueryPerformanceFrequency(&ticksPerSec);
		if (!ticksPerSec.QuadPart)
		{
			errno = ENOTSUP;
			fprintf(stderr, "clock_gettime_monotonic: QueryPerformanceFrequency failed\n");
			exit(-1);
		}
	}

	QueryPerformanceCounter(&ticks);

	tv->tv_sec = (long)(ticks.QuadPart / ticksPerSec.QuadPart);
	tv->tv_nsec = (long)(((ticks.QuadPart % ticksPerSec.QuadPart) * NS_PER_SEC) / ticksPerSec.QuadPart);
}

int clock_gettime(clockid_t clockid, struct timespec *tp)
{
	clock_gettime_monotonic(tp);
	return 0;
}
#endif
