#ifndef ASSERT_H
#define ASSERT_H

#include <stdlib.h>
#define assert(cond) do { if (!(cond)) abort(); } while (0)

#endif /* ASSERT_H */
