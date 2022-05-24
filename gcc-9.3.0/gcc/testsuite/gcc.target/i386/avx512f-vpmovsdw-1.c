/* { dg-do compile } */
/* { dg-options "-mavx512f -O2" } */
/* { dg-final { scan-assembler-times "vpmovsdw\[ \\t\]+\[^\{\n\]*(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vpmovsdw\[ \\t\]+\[^\{\n\]*%ymm\[0-9\]+(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vpmovsdw\[ \\t\]+\[^\{\n\]*%ymm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vpmovsdw\[ \\t\]+\[^\{\n\]*%ymm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m512i s;
volatile __m256i res;
volatile __mmask16 m;

void extern
avx512f_test (void)
{
  res = _mm512_cvtsepi32_epi16 (s);
  res = _mm512_mask_cvtsepi32_epi16 (res, m, s);
  res = _mm512_maskz_cvtsepi32_epi16 (m, s);
  _mm512_mask_cvtsepi32_storeu_epi16 ((void *) &res, m, s);
}
