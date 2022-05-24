/* { dg-do run } */
/* { dg-require-effective-target ssse3 } */
/* { dg-options "-O2 -fno-strict-aliasing -mssse3" } */

#ifndef CHECK_H
#define CHECK_H "ssse3-check.h"
#endif

#ifndef TEST
#define TEST ssse3_test
#endif

#include CHECK_H

#include "ssse3-vals.h"

#include <tmmintrin.h>

/* Test the 64-bit form */
static void
ssse3_test_pabsd (int *i1, int *r)
{
  __m64 t1 = *(__m64 *) i1;
  *(__m64 *) r = _mm_abs_pi32 (t1);
  _mm_empty ();
}

/* Test the 128-bit form */
static void
ssse3_test_pabsd128 (int *i1, int *r)
{
  /* Assumes incoming pointers are 16-byte aligned */
  __m128i t1 = *(__m128i *) i1;
  *(__m128i *) r = _mm_abs_epi32 (t1);
}

/* Routine to manually compute the results */
static void
compute_correct_result (int *i1, int *r)
{
  int i;

  for (i = 0; i < 4; i++)
    if (i1[i] < 0)
      r[i] = -i1[i];
    else
      r[i] = i1[i];
}

static void
TEST (void)
{
  int i;
  int r [4] __attribute__ ((aligned(16)));
  int ck [4];
  int fail = 0;

  for (i = 0; i < 256; i += 4)
    {
      /* Manually compute the result */
      compute_correct_result(&vals[i + 0], ck);

      /* Run the 64-bit tests */
      ssse3_test_pabsd (&vals[i + 0], &r[0]);
      ssse3_test_pabsd (&vals[i + 2], &r[2]);
      fail += chk_128 (ck, r);

      /* Run the 128-bit tests */
      ssse3_test_pabsd128 (&vals[i + 0], r);
      fail += chk_128(ck, r);
    }

  if (fail != 0)
    abort ();
}
