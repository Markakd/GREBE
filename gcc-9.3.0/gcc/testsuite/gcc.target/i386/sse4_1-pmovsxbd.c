/* { dg-do run } */
/* { dg-require-effective-target sse4 } */
/* { dg-options "-O2 -msse4.1" } */

#ifndef CHECK_H
#define CHECK_H "sse4_1-check.h"
#endif

#ifndef TEST
#define TEST sse4_1_test
#endif

#include CHECK_H

#include <smmintrin.h>

#define NUM 128

static void
TEST (void)
{
  union
    {
      __m128i x[NUM / 4];
      int i[NUM];
      char c[NUM * 4];
    } dst, src;
  int i, sign = 1;

  for (i = 0; i < NUM; i++)
    {
      src.c[(i % 4) + (i / 4) * 16] = i * i * sign;
      sign = -sign;
    }

  for (i = 0; i < NUM; i += 4)
    dst.x [i / 4] = _mm_cvtepi8_epi32 (src.x [i / 4]);

  for (i = 0; i < NUM; i++)
    if (src.c[(i % 4) + (i / 4) * 16] != dst.i[i])
      abort ();
}
