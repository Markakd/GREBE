/* { dg-do compile } */
/* { dg-options "-O2 -mavx512f" } */
/* { dg-final { scan-assembler-times "vcvttss2sil?\[ \\t\]+\[^\{\n\]*%xmm\[0-9\]+.{6}(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vcvttss2sil?\[ \\t\]+\[^\{\n\]*\{sae\}\[^\n\]*%xmm\[0-9\]+.{6}(?:\n|\[ \\t\]+#)" 1 } } */
#include <immintrin.h>

volatile __m128 x;
volatile int y;

void extern
avx512f_test (void)
{
  y = _mm_cvttss_i32 (x);
  y = _mm_cvtt_roundss_i32 (x, _MM_FROUND_NO_EXC);
}
