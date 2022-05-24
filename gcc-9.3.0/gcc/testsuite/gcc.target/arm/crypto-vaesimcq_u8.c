/* { dg-do compile } */
/* { dg-require-effective-target arm_crypto_ok } */
/* { dg-add-options arm_crypto } */

#include "arm_neon.h"

int
foo (void)
{
  uint8x16_t a, b;
  int i = 0;

  for (i = 0; i < 16; ++i)
    a[i] = i;

  b = vaesimcq_u8 (a);
  return b[0];
}

/* { dg-final { scan-assembler "aesimc.8\tq\[0-9\]+, q\[0-9\]+" } } */
