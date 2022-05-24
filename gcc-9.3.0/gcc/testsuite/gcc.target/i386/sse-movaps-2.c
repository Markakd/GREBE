/* { dg-do run } */
/* { dg-options "-O2 -msse" } */
/* { dg-require-effective-target sse } */

#ifndef CHECK_H
#define CHECK_H "sse-check.h"
#endif

#ifndef TEST
#define TEST sse_test
#endif

#include CHECK_H

#include <xmmintrin.h>

static void
__attribute__((noinline, unused))
test (float *e, __m128 a)
{
  _mm_store_ps (e, a); 
}

static void
TEST (void)
{
  union128 u;
  float e[4] __attribute__ ((aligned (16))) = {0.0};

  u.x = _mm_set_ps (2134.3343,1234.635654, 1.414, 3.3421);

  test (e, u.x);

  if (check_union128 (u, e))
    abort ();
}
