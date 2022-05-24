/* { dg-do compile } */
/* { dg-options "-mavx512f -O2" } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\[^\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)"  3 } } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)"  3 } } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\\S*,\[ \\t\]+\{sae\}\[^\n\]*%zmm\[0-9\]+\[^\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\\S*,\[ \\t\]+\{sae\}\[^\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vrndscaleps\[ \\t\]+\\S*,\[ \\t\]+\{sae\}\[^\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m512 x;

void extern
avx512f_test (void)
{
  x = _mm512_roundscale_ps (x, 0x42);
  x = _mm512_ceil_ps (x);
  x = _mm512_floor_ps (x);
  x = _mm512_mask_roundscale_ps (x, 2, x, 0x42);
  x = _mm512_mask_ceil_ps (x, 2, x);
  x = _mm512_mask_floor_ps (x, 2, x);
  x = _mm512_maskz_roundscale_ps (2, x, 0x42);

  x = _mm512_roundscale_round_ps (x, 0x42, _MM_FROUND_NO_EXC);
  x = _mm512_mask_roundscale_round_ps (x, 2, x, 0x42, _MM_FROUND_NO_EXC);
  x = _mm512_maskz_roundscale_round_ps (2, x, 0x42, _MM_FROUND_NO_EXC);
}
