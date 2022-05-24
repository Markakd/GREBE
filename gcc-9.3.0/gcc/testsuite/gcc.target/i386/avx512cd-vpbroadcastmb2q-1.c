/* { dg-do compile } */
/* { dg-options "-mavx512cd -O2" } */
/* { dg-final { scan-assembler-times "vpbroadcastmb2q\[ \\t\]+\[^\{\n\]*%k\[0-7\]\[^\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m512i x;
volatile __mmask8 m8;

void extern
avx512f_test (void)
{
  x = _mm512_broadcastmb_epi64 (m8);
}
