/* { dg-do compile { target { powerpc*-*-* && lp64 } } } */
/* { dg-skip-if "" { powerpc*-*-darwin* } } */
/* { dg-require-effective-target powerpc_p8vector_ok } */
/* { dg-options "-mdejagnu-cpu=power8 -O2" } */

#include <stdint.h>

typedef union
{
  float value;
  uint32_t word;
} ieee_float_shape_type;

float
mask_and_float_sign (float f)
{ 
  ieee_float_shape_type u;

  u.value = f;
  u.word &= 0x80000000;

  return u.value;
}

/* { dg-final { scan-assembler     "\[ \t\]xxland " } } */
/* { dg-final { scan-assembler-not "\[ \t\]and "    } } */
/* { dg-final { scan-assembler-not "\[ \t\]mfvsrd " } } */
/* { dg-final { scan-assembler-not "\[ \t\]stxv"    } } */
/* { dg-final { scan-assembler-not "\[ \t\]lxv"     } } */
/* { dg-final { scan-assembler-not "\[ \t\]srdi "   } } */
