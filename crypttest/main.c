#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>

#include "sm_loader.h"
#include "ctest.h"
#include "other.h"


static char buffer[32];
static char mac[16];


int putchar(int c)
{
    P1OUT = c;
    P1OUT |= 0x80;
    return c;
}


void print_bytes(const char* bytes, size_t n)
{
    int i;
    for (i = 0; i < n; i++)
        printf("%02x", bytes[i] & 0xff);
}


int main()
{
    size_t pstart;
    size_t pend;
    size_t ret;
    size_t i;

    WDTCTL = WDTPW | WDTHOLD;

    printf("Start of main()\n");

    printf("Trying to read code of ctest after reset (should be all zeros)!\n");
    pstart = (size_t)crypt_ctest.public_start;
    pend   = (size_t)crypt_ctest.public_end;
    for (i = pstart; i < (pstart + 8) && i < pend; i += 2) {
        print_bytes((const char *)i, 2);
        printf("\n");
    }

    printf("Protecting loader ... ");
    protect_sm(&sm_loader);
    printf("done\n");

    printf("Loading/Decrypting ctest ... ");
    ret = sm_loader_load(&crypt_ctest);
    if (ret != 1) {
        printf("failed\n");
        return -1;
    }
    printf("done\n");

    printf("Destroying loader ... ");
    sm_loader_destroy();
    printf("done\n");

    printf("Direct call to ctest_hello():\n");
    ret = ctest_hello(buffer, 32);
    for (i = 0; i < ret; i++)
        putchar(buffer[i]);

    printf("Protecting other ... ");
    protect_sm(&other);
    printf("done\n");

    printf("Indirect call to ctest_hello() via other_call_ctest():\n");
    ret = other_call_ctest(buffer, 32, mac);
    printf("Data: "); print_bytes(buffer, ret);
    printf(" MAC: "); print_bytes(mac, 16);
    printf("\n");

    printf("Trying to read code of ctest (should trigger violation)!\n");
    pstart = (size_t)crypt_ctest.public_start;
    pend   = (size_t)crypt_ctest.public_end;
    for (i = pstart; i < pend; i += 2) {
        print_bytes((const char *)i, 2);
        printf("\n");
    }

    printf("End of main()\n");

    return 0;
}
