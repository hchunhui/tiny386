/* i386.c with a fast path in front of its interpreter (fast.h): build this instead of i386.c, with -DUSE_FAST
 * (make USE_FAST=y) */
#ifdef USE_FAST
#define cpui386_step tiny386_step
#define cpui386_reset tiny386_reset
#include "i386.c"
#undef cpui386_step
#undef cpui386_reset
#include "fast.h"
#endif
