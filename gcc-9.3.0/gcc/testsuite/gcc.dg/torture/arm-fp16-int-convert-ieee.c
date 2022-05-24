/* Test floating-point conversions.  Standard types and __fp16.  */
/* { dg-do run { target arm*-*-* } } */
/* { dg-options "-mfp16-format=ieee" } */

#include "fp-int-convert.h"
#define FP16_MANT_DIG 11
#define FP16_MAX_EXP 16

int
main (void)
{
  TEST_I_F(signed char, unsigned char, float, FP16_MANT_DIG, FP16_MAX_EXP);
  TEST_I_F(signed short, unsigned short, float, FP16_MANT_DIG, FP16_MAX_EXP);
  TEST_I_F(signed int, unsigned int, float, FP16_MANT_DIG, FP16_MAX_EXP);
  TEST_I_F(signed long, unsigned long, float, FP16_MANT_DIG, FP16_MAX_EXP);
  TEST_I_F(signed long long, unsigned long long, float, FP16_MANT_DIG, FP16_MAX_EXP);
  exit (0);
}
