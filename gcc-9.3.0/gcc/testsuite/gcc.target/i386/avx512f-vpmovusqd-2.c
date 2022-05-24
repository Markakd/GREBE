/* { dg-do run } */
/* { dg-options "-O2 -mavx512f" } */
/* { dg-require-effective-target avx512f } */

#define AVX512F

#include "avx512f-helper.h"

#define SIZE (AVX512F_LEN / 64)
#include "avx512f-mask-type.h"
#define SIZE_HALF (AVX512F_LEN_HALF / 32)
#include <limits.h>

void
CALC (unsigned int *r, unsigned long long *s, int mem)
{
  int i;
  int len = mem ? SIZE : SIZE_HALF;
  for (i = 0; i < len; i++)
    r[i] = (i < SIZE) ? ((s[i] > UINT_MAX) ? UINT_MAX : s[i]) : 0;
}

void
TEST (void)
{
  int i;
  UNION_TYPE (AVX512F_LEN_HALF, i_ud) res1, res2, res3;
  unsigned int res4[SIZE_HALF];
  UNION_TYPE (AVX512F_LEN, i_uq) src;
  MASK_TYPE mask = MASK_VALUE;
  unsigned int res_ref[SIZE_HALF];
  unsigned int res_ref2[SIZE_HALF];

  for (i = 0; i < SIZE; i++)
    {
      src.a[i] = 1 + 34 * i;
      res2.a[i] = DEFAULT_VALUE;
      res4[i] = DEFAULT_VALUE;
    }

  for (i = SIZE; i < SIZE_HALF; i++)
    {
      res_ref2[i] = DEFAULT_VALUE * 2;
      res4[i] = DEFAULT_VALUE * 2;
    }

  res1.x = INTRINSIC (_cvtusepi64_epi32) (src.x);
  res2.x = INTRINSIC (_mask_cvtusepi64_epi32) (res2.x, mask, src.x);
  res3.x = INTRINSIC (_maskz_cvtusepi64_epi32) (mask, src.x);

  CALC (res_ref, src.a, 0);

  if (UNION_CHECK (AVX512F_LEN_HALF, i_ud) (res1, res_ref))
    abort ();

  MASK_MERGE (i_ud) (res_ref, mask, SIZE);
  if (UNION_CHECK (AVX512F_LEN_HALF, i_ud) (res2, res_ref))
    abort ();

  MASK_ZERO (i_ud) (res_ref, mask, SIZE);
  if (UNION_CHECK (AVX512F_LEN_HALF, i_ud) (res3, res_ref))
    abort ();

  CALC (res_ref2, src.a, 1);
  INTRINSIC (_mask_cvtusepi64_storeu_epi32) (res4, mask, src.x);

  MASK_MERGE (i_d) (res_ref2, mask, SIZE);
  if (checkVi (res4, res_ref2, SIZE_HALF))
    abort ();
}
