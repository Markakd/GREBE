/* { dg-do compile } */
/* { dg-options "-O0 -mavx -mvzeroupper -dp" } */

#include <immintrin.h>

extern __m256 x, y;

void
foo ()
{
  x = y;
  _mm256_zeroall ();
}

/* { dg-final { scan-assembler-not "avx_vzeroupper" } } */
