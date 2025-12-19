// tiny glib, use at your own risk!
// XXX: only little endian is supported now
#ifndef _GLIB_H_
#define _GLIB_H_
#define G_BYTE_ORDER G_LITTLE_ENDIAN
#define G_LITTLE_ENDIAN 1234
#define G_BIG_ENDIAN 4321

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

typedef char *gchar;
typedef int gint;
typedef _Bool gboolean;

#define G_GNUC_PRINTF(...)
#define G_STATIC_ASSERT _Static_assert
#define G_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define G_N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))

#define __LOG(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define g_debug(...) __LOG(__VA_ARGS__)
#define g_warning(...) __LOG(__VA_ARGS__)
#define g_error(...) __LOG(__VA_ARGS__)
#define g_critical(...) __LOG(__VA_ARGS__)
#define g_vsnprintf vsnprintf
#define g_snprintf snprintf
#define g_assert_not_reached __builtin_unreachable
#define g_assert assert
#define g_getenv getenv
#define g_strerror strerror
#define g_realloc realloc
#define g_malloc malloc
#define g_free free
#define g_ascii_strcasecmp strcasecmp
#define g_warn_if_reached(...)
#define g_warn_if_fail(...)
#define g_return_val_if_fail(a, v) if (!(a)) return (v)
#define g_return_if_fail(a) if (!(a)) return
#define g_new(stype, n) ((stype *) g_malloc((n) * sizeof (stype)))
#define g_new0(stype, n) ((stype *) g_malloc0((n) * sizeof (stype)))

#define GUINT16_TO_BE(a) htons(a)
#define GUINT32_TO_BE(a) htonl(a)
#define GUINT16_FROM_BE(a) ntohs(a)
#define GUINT32_FROM_BE(a) ntohl(a)
#define GINT16_TO_BE(a) htons(a)
#define GINT32_TO_BE(a) htonl(a)
#define GINT16_FROM_BE(a) ((int16_t) ntohs(a))
#define GINT32_FROM_BE(a) ((int32_t) ntohl(a))
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

static char *g_strdup(const char *s)
{
	if (s) return strdup(s);
	return NULL;
}

static void *g_malloc0(size_t size)
{
	void *p = g_malloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

static int g_str_has_prefix(const char *a, const char *b)
{
	int len = strlen(b);
	return strncmp(a, b, len) == 0;
}

typedef void *GRand;

static int g_rand_int_range(void *_, int a, int b)
{
	return rand() % (b - a) + a;
}

static void *g_rand_new(void)
{
	srand(time(NULL));
	return (void *) 1;
}

#define g_rand_free(...)
#endif
