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
      unsigned int i[NUM];
      unsigned short s[NUM * 2];
    } dst, src;
  int i;

  for (i = 0; i < NUM; i++)
    {
      src.s[(i % 4) + (i / 4) * 8] = i * i;
      if ((i % 4))
	src.s[(i % 4) + (i / 4) * 8] |= 0x8000;
    }

  for (i = 0; i < NUM; i += 4)
    dst.x [i / 4] = _mm_cvtepu16_epi32 (src.x [i / 4]);

  for (i = 0; i < NUM; i++)
    if (src.s[(i % 4) + (i / 4) * 8] != dst.i[i])
      abort ();
}
