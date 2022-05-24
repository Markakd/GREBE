/* { dg-do run } */
/* { dg-require-effective-target avx } */
/* { dg-options "-O2 -mavx" } */

#include "avx-check.h"

static void
__attribute__((noinline, unused))
test (double *e, __m256d a)
{
  return _mm256_storeu_pd (e, a);
}

void static
avx_test (void)
{
  union256d u;
  double e [4] = {0.0};

  u.x = _mm256_set_pd (39578.467285, 7856.342941, 85632.783567, 47563.234215);

  test (e, u.x);

  if (check_union256d (u, e))
    abort ();
}
