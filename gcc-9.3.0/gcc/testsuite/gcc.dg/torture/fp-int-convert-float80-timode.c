/* Test floating-point conversions.  __float80 type with TImode.  */
/* Origin: Joseph Myers <joseph@codesourcery.com> */
/* { dg-do run { target i?86-*-* x86_64-*-* ia64-*-* } } */
/* { dg-options "" } */
/* { dg-options "-mmmx" { target { { i?86-*-* x86_64-*-* } && ia32 } } } */

#include "fp-int-convert.h"

#define FLOAT80_MANT_DIG 64
#define FLOAT80_MAX_EXP 16384

int
main (void)
{
  TEST_I_F(TItype, UTItype, __float80, FLOAT80_MANT_DIG, FLOAT80_MAX_EXP);
  exit (0);
}
