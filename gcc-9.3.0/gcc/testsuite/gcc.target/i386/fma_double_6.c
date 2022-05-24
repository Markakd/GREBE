/* { dg-do compile } */
/* { dg-options "-O2 -Wno-attributes -mfpmath=sse -mfma" } */

/* Test that the compiler properly optimizes floating point multiply
   and add instructions into FMA3 instructions.  */

#define TYPE double

#include "fma_6.h"

/* { dg-final { scan-assembler-times "vfmadd132sd" 8  } } */
/* { dg-final { scan-assembler-times "vfmsub132sd" 8  } } */
/* { dg-final { scan-assembler-times "vfnmadd132sd" 8  } } */
/* { dg-final { scan-assembler-times "vfnmsub132sd" 8  } } */
