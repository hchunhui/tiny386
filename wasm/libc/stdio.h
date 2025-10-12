#ifndef STDIO_H
#define STDIO_H

#include <stddef.h>
#include <stdarg.h>

typedef int64_t off_t;

typedef struct {
	int fd;
	int64_t size;
	int64_t i;
} FILE;

extern FILE *stdout, *stderr;

int putchar(int c);
int fputc(int c, FILE *fp);
int vprintf(const char *fmt, va_list args);
int printf(const char *fmt, ...);
int vfprintf(FILE *fp, const char *fmt, va_list args);
int fprintf(FILE *fp, const char *fmt, ...);
int fflush(FILE *fp);

enum {
	SEEK_SET,
	SEEK_CUR,
	SEEK_END
};

FILE *fopen(const char *path, const char *mode);
void rewind(FILE *fp);
off_t ftell(FILE *fp);
#define ftello ftell
int fseek(FILE *fp, off_t offset, int whence);
#define fseeko fseek
int fclose(FILE *fp);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *fp);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp);
char *fgets(char *s, int size, FILE *fp);
void perror(const char *s);

#endif /* STDIO_H */
