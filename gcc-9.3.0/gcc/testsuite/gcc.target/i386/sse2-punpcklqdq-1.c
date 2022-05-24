/* { dg-do run } */
/* { dg-options "-O2 -msse2" } */
/* { dg-require-effective-target sse2 } */

#ifndef CHECK_H
#define CHECK_H "sse2-check.h"
#endif

#ifndef TEST
#define TEST sse2_test
#endif

#include CHECK_H

#include <emmintrin.h>

static __m128i
__attribute__((noinline, unused))
test (__m128i s1, __m128i s2)
{
  return _mm_unpacklo_epi64 (s1, s2); 
}

static void
TEST (void)
{
  union128i_q u, s1, s2;
  long long  e[2];
   
  s1.x = _mm_set_epi64x (10,-40);
  s2.x = _mm_set_epi64x (1134, -7839);
  u.x = test (s1.x, s2.x); 
  
  e[0] = s1.a[0];
  e[1] = s2.a[0];

  if (check_union128i_q (u, e))
    abort ();
}
