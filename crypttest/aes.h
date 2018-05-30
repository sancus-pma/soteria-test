#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

extern uint8_t AES128_RoundKey[176];
extern uint8_t AES128_Iv[16];

extern const uint8_t *AES128_Input;
extern uint8_t       *AES128_Output;
extern uint16_t       AES128_Length;

int AES128_CCM_decrypt(void);

#endif //_AES_H_
