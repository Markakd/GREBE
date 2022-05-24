/* Test floating-point conversions.  __float80 type.  */
/* Origin: Joseph Myers <joseph@codesourcery.com> */
/* { dg-do run { target i?86-*-* x86_64-*-* ia64-*-* } } */
/* { dg-options "" } */

#include "fp-int-convert.h"

#define FLOAT80_MANT_DIG 64
#define FLOAT80_MAX_EXP 16384

int
main (void)
{
  TEST_I_F(signed char, unsigned char, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  TEST_I_F(signed short, unsigned short, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  TEST_I_F(signed int, unsigned int, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  TEST_I_F(signed long, unsigned long, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  TEST_I_F(signed long long, unsigned long long, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  exit (0);
}
