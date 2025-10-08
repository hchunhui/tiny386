#ifndef MATH_H
#define MATH_H

#include <stddef.h>

// taken from musllibc
double frexp(double x, int *e);

// use compiler builtin
#define copysign __builtin_copysign
#define signbit __builtin_signbit
#define frexp __builtin_frexp
#define fabs __builtin_fabs
#define floor __builtin_floor
#define ceil __builtin_ceil
#define trunc __builtin_trunc
#define isunordered __builtin_isunordered
#define isnan __builtin_isnan
#define isfinite __builtin_isfinite
#define sqrt __builtin_sqrt

// provided by js runtime
double sin(double x);
double cos(double x);
double pow(double x, double y);
double log10(double x);
double log2(double x);
double tan(double x);
double atan2(double y, double x);
double round(double x);

#endif /* MATH_H */
