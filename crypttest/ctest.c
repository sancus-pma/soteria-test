#include <stdio.h>
#include "ctest.h"

DECLARE_CRYPT_SM(crypt_ctest, 0x1234);

static const char SM_DATA("crypt_ctest") string[] = "Hello Cryptworld!\n";

size_t ctest_hello(char *buffer, size_t n)
{
    size_t i, j;

    for (i = 0; string[i] != '\0'; i++);

    for (j = 0; j < i && j < n; j++)
        buffer[j] = string[j];

    return i < n ? i : n;
}
