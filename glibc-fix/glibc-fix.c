#define _GNU_SOURCE
#include <dlfcn.h>

#ifndef __x86_64__
#error "unsupported"
#endif

__asm__(".symver old_dlvsym,dlvsym@GLIBC_2.2.5");
void *old_dlvsym(void *handle, const char *symbol, const char *version);

extern void _init(void);
extern void (*__init_array_start [])(int, char **, char **);
extern void (*__init_array_end [])(int, char **, char **);
static void csu_init(int argc, char **argv, char **envp)
{
	_init ();
	const size_t size = __init_array_end - __init_array_start;
	for (size_t i = 0; i < size; i++) {
		(*__init_array_start [i])(argc, argv, envp);
	}
}

int __libc_start_main(int (*main) (int, char **, char **),
		      int argc,
		      char **argv,
		      void (*init) (int, char **, char **),
		      void (*fini) (void),
		      void (*rtld_fini) (void),
		      void *stack_end)
{
	typeof(&__libc_start_main) orig;
	orig = old_dlvsym(RTLD_NEXT, "__libc_start_main", "GLIBC_2.34");
	if (orig) {
		return orig(main, argc, argv, init, fini, rtld_fini, stack_end);
	}
	orig = old_dlvsym(RTLD_NEXT, "__libc_start_main", "GLIBC_2.2.5");
	return orig(main, argc, argv, csu_init, fini, rtld_fini, stack_end);
}

long int __isoc23_strtol(const char *__restrict __nptr,
			 char **__restrict __endptr, int __base)
{
	static typeof(&__isoc23_strtol) orig;
	if (!orig)
		orig = old_dlvsym(RTLD_NEXT, "__isoc23_strtol", "GLIBC_2.38");
	if (!orig)
		orig = old_dlvsym(RTLD_NEXT, "strtol", "GLIBC_2.2.5");
	return orig(__nptr, __endptr, __base);
}

struct stat;
int stat(const char *__path, struct stat *__statbuf)
{
	static int (*orig)(const char *, struct stat *);
	static int (*xorig)(int, const char *, struct stat *);
	if (!orig && !xorig) {
		orig = old_dlvsym(RTLD_NEXT, "stat", "GLIBC_2.33");
		if (!orig)
			xorig = old_dlvsym(RTLD_NEXT, "__xstat", "GLIBC_2.2.5");
	}
	if (orig)
		return orig(__path, __statbuf);
	return xorig(0, __path, __statbuf);
}
