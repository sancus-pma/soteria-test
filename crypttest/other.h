#ifndef _OTHER_H
#define _OTHER_H

#include <sancus/sm_support.h>
#include "ctest.h"

extern struct SancusModule other;

size_t SM_ENTRY("other") other_call_ctest(char *buffer, size_t n, char *mac);

#endif /* _OTHER_H */
