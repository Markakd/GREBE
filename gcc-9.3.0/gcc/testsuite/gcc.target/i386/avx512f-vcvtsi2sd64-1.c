/* { dg-do compile { target { ! ia32 } } } */
/* { dg-options "-mavx512f -O2" } */
/* { dg-final { scan-assembler-times "vcvtsi2sdq\[ \\t\]+\[^%\n\]*%r\[^\{\n\]*\{ru-sae\}\[^\{\n\]*%xmm\[0-9\]+(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m128d x;
volatile long long n;

void extern
avx512f_test (void)
{
  x = _mm_cvt_roundi64_sd (x, n, _MM_FROUND_TO_POS_INF | _MM_FROUND_NO_EXC);
}
