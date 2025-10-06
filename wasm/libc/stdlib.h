#ifndef STDLIB_H
#define STDLIB_H

#include <stddef.h>

void *malloc(unsigned long n);
void free(void *p);
void *calloc(size_t nmemb, size_t size);

void srand(unsigned s);
int rand(void);

_Noreturn void __abort(const char *);
#define TOSTR(y) TOSTR0(y)
#define TOSTR0(x) #x
#define abort() __abort("FILE: " __FILE__ ", LINE: " TOSTR(__LINE__))

_Noreturn void exit(int status);

int atoi(const char *s);
#define atol atoi

#endif /* STDLIB_H */
