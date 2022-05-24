/* { dg-do compile } */
/* { dg-options "-mavx512f -O2" } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)"  1 } } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\n\]*\{rn-sae\}\[^\{\n\]*%zmm\[0-9\]+(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\n\]*\{rd-sae\}\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}(?:\n|\[ \\t\]+#)" 1 } } */
/* { dg-final { scan-assembler-times "vcvtudq2ps\[ \\t\]+\[^\n\]*\{rz-sae\}\[^\{\n\]*%zmm\[0-9\]+\{%k\[1-7\]\}\{z\}(?:\n|\[ \\t\]+#)" 1 } } */

#include <immintrin.h>

volatile __m512i s;
volatile __m512 res;
volatile __mmask8 m;

void extern
avx512f_test (void)
{
  res = _mm512_cvtepu32_ps (s);
  res = _mm512_mask_cvtepu32_ps (res, m, s);
  res = _mm512_maskz_cvtepu32_ps (m, s);
  res = _mm512_cvt_roundepu32_ps (s, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
  res = _mm512_mask_cvt_roundepu32_ps (res, m, s, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
  res = _mm512_maskz_cvt_roundepu32_ps (m, s, _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC);
}
