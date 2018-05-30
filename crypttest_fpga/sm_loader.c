#include "sm_loader.h"
#include "aes.h"

#define SM_LOADER_KEYLEN 16

DECLARE_SM(sm_loader, 0x1234);


static unsigned char SM_DATA("sm_loader") key[SM_LOADER_KEYLEN];
static unsigned char SM_DATA("sm_loader") iv[SM_LOADER_KEYLEN];


static int SM_FUNC("sm_loader") decrypt(const void *key, const void *iv,
                                        const void *src, void *dst, size_t n)
{
    const uint8_t *k    = key;
    const uint8_t *ivec = iv;
    const uint8_t *s    = src;
    uint8_t *d = dst;
    size_t i;
    int ret;

    // initialize RoundKey
    for (i = 0; i < SM_LOADER_KEYLEN; i++)
        AES128_RoundKey[i] = k[i];

    // initialize IV
    for (i = 0; i < SM_LOADER_KEYLEN; i++)
        AES128_Iv[i] = ivec[i];

    // set AES parameters
    AES128_Input  = s;
    AES128_Output = d;
    AES128_Length = n;

    // perform the decryption
    ret = AES128_CCM_decrypt();

    // wipe all AES state information from RAM
    for (i = 0; i < SM_LOADER_KEYLEN; i++)
        AES128_Iv[i] = 0x00;
    for (i = 0; i < 176; i++)
        AES128_RoundKey[i] = 0x00;

    return ret;
}


int sm_loader_load(struct SancusCryptModule *scm)
{
    size_t pstart  = (size_t)scm->public_start;
    size_t pend    = (size_t)scm->public_end;
    size_t pcstart = (size_t)scm->public_start_crypt;
    size_t pcend   = (size_t)scm->public_end_crypt;
    size_t i;
    int ret;

    // check boundaries
    if (pend < pstart || pcend < pcstart)
        return 0;

    // check sizes
    if ((pend - pstart) != (pcend - pcstart))
        return 0;

    // check if sizes are a multiple of the AES block size
    if ((pend - pstart) % SM_LOADER_KEYLEN != 0)
        return 0;

    // get scm->name length
    for (i = 0; scm->name[i] != '\0'; i++);

    // derive decryption key
    if (hmac_sign(key, scm->name, i) == 0)
        return 0;

    // derive the IV for CCM mode
    if (hmac_sign(iv, key, SM_LOADER_KEYLEN) == 0)
        return 0;

    // TODO: disable interrupts

    // decrypt module and check integrity in CCM mode
    if (decrypt(key, iv, scm->public_start_crypt,
                scm->public_start, pend - pstart) == 0)
        return 0;

    // protect the module (should prevent read access)
    ret = protect_sm((struct SancusModule *)scm);

    // TODO: enable interrupts

    return ret;
}


void sm_loader_destroy(void)
{
    size_t i;

    // wipe the iv
    for (i = 0; i < SM_LOADER_KEYLEN; i++)
        iv[i] = 0x00;

    // wipe the key
    for (i = 0; i < SM_LOADER_KEYLEN; i++)
        key[i] = 0x00;

    // call unprotect
    unprotect_sm();
}
