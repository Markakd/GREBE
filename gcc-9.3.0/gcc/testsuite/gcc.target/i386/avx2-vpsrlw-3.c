/* { dg-do run } */
/* { dg-options "-mavx2 -mno-prefer-avx128 -O2 -ftree-vectorize -save-temps" } */
/* { dg-require-effective-target avx2 } */


#define TYPE unsigned short
#define UN_OP(a) ((a) >> (5))

#include "avx2-vpop-check.h"

/* { dg-final { scan-assembler-times "vpsrlw\[ \\t\]+\[^\n\]*%ymm\[0-9\]" 1 } } */
