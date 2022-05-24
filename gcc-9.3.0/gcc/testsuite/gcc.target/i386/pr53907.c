/* { dg-do compile } */
/* { dg-options "-O -msse2" } */

#include <emmintrin.h>

__extension__ typedef __UINTPTR_TYPE__ uintptr_t;

__m128i x(char *s)
{
  __m128i sz,z,mvec;
  s-=((uintptr_t) s)%16;
  sz=_mm_load_si128((__m128i *)s);
  return sz;
}

/* { dg-final { scan-assembler "movdqa|movaps" } } */
