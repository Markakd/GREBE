/* { dg-do compile } */
/* { dg-options "-mavx512er -O2" } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*\{sae\}\[^\n\]*%zmm\[0-9\]+\[^\{\]*(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*\{sae\}\[^\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vexp2pd\[ \\t\]+\[^\{\n\]*\{sae\}\[^\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m512d x;
volatile __mmask8 m;

void extern
avx512er_test (void)
{
  x = _mm512_exp2a23_pd (x);
  x = _mm512_mask_exp2a23_pd (x, m, x);
  x = _mm512_maskz_exp2a23_pd (m, x);
  x = _mm512_exp2a23_round_pd (x, _MM_FROUND_NO_EXC);
  x = _mm512_mask_exp2a23_round_pd (x, m, x, _MM_FROUND_NO_EXC);
  x = _mm512_maskz_exp2a23_round_pd (m, x, _MM_FROUND_NO_EXC);
}
