#include "other.h"

DECLARE_SM(other, 0x1234);

size_t other_call_ctest(char *buffer, size_t n, char *mac)
{
    size_t ret;

    ret = ctest_hello(buffer, n);
    hmac_sign(mac, buffer, ret);

    return ret;
}
