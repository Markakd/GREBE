/* { dg-do run } */
/* { dg-options "-O2 -mfpmath=sse -msse2" } */
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
test (__m128d s1, double *p)
{
  return _mm_loadh_pd (s1, p); 
}

static void
TEST (void)
{
  union128d u, s1;
  double s2[2] = {41124.234,2344.2354};
  double e[2];
   
  s1.x = _mm_set_pd (2134.3343,1234.635654);
  u.x = test (s1.x, s2); 

  e[0] = s1.a[0];
  e[1] = s2[0];

  if (check_union128d (u, e))
    abort ();
}
