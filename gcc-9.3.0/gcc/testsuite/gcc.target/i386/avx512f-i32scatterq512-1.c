/* { dg-do compile } */
/* { dg-options "-mavx512f -O2" } */
/* { dg-final { scan-assembler-times "vpscatterdq\[ \\t\]+\[^\{\n\]*zmm\[0-9\]\[^\n\]*ymm\[0-9\]\[^\n\]*{%k\[1-7\]}(?:\n|\[ \\t\]+#)" 2 } } */

#include <immintrin.h>

volatile __m512i src;
volatile __m256i idx;
volatile __mmask8 m8;
long long *addr;

void extern
avx512f_test (void)
{
  _mm512_i32scatter_epi64 (addr, idx, src, 8);
  _mm512_mask_i32scatter_epi64 (addr, m8, idx, src, 8);
}
