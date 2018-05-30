#ifndef _CTEST_H
#define _CTEST_H

#include <sancus/sm_crypt.h>

extern struct SancusCryptModule crypt_ctest;

size_t SM_ENTRY("crypt_ctest") ctest_hello(char *buffer, size_t n);

#endif /* _CTEST_H */
