#ifndef STRING_H
#define STRING_H

#include <stddef.h>

void *memset(void *s, int c, unsigned long n);
void *memcpy(void *dest, const void *src, unsigned long n);
char *strcpy(char *dest, const char *src);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
char *strdup(const char *s);
int memcmp(const void *s1, const void *s2, size_t n);
char *strchr(const char *s, int c);

//#define strchr __builtin_strchr
//#define memcmp __builtin_memcmp


#endif /* STRING_H */
