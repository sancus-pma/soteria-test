#include <stdint.h>

//XXX SM_FUNC("sm_loader")
uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}
