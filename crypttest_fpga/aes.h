#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <sancus/sm_support.h>

extern SM_DATA("sm_loader") uint8_t AES128_RoundKey[176];
extern SM_DATA("sm_loader") uint8_t AES128_Iv[16];

extern SM_DATA("sm_loader") const uint8_t *AES128_Input;
extern SM_DATA("sm_loader") uint8_t       *AES128_Output;
extern SM_DATA("sm_loader") uint16_t       AES128_Length;

int SM_FUNC("sm_loader") AES128_CCM_decrypt(void);

#endif //_AES_H_
