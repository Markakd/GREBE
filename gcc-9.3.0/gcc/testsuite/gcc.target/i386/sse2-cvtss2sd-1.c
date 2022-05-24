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

static __m128d 
__attribute__((noinline, unused))
test (__m128d a, __m128 b)
{
  return _mm_cvtss_sd (a, b); 
}

static void
TEST (void)
{
  union128d u, s1;
  union128 s2;
  double e[2];

  s1.x = _mm_set_pd (123.321, 456.987);
  s2.x = _mm_set_ps (123.321, 456.987, 666.45, 231.987);

  u.x = test (s1.x, s2.x);

  e[0] = (double)s2.a[0];
  e[1] = s1.a[1];

  if (check_union128d (u, e))
    abort ();
}
