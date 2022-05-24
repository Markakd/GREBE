/* { dg-do run } */
/* { dg-options "-O2 -mavx512f" } */
/* { dg-require-effective-target avx512f } */

#define AVX512F

#include "avx512f-helper.h"

#include <math.h>
#define SIZE (AVX512F_LEN / 32)
#include "avx512f-mask-type.h"

__mmask8 dst_ref;

#if AVX512F_LEN == 512
#undef CMP
#define CMP(imm, rel)					\
    dst_ref = 0;					\
    for (i = 0; i < 8; i++)				\
    {							\
      dst_ref = ((rel) << i) | dst_ref;			\
    }							\
    source1.x = _mm512_loadu_si512 (s1);		\
    source2.x = _mm512_loadu_si512 (s2);		\
    dst1 = _mm512_cmp_epi64_mask (source1.x, source2.x, imm);\
    dst2 = _mm512_mask_cmp_epi64_mask (mask, source1.x, source2.x, imm);\
    if (dst_ref != dst1) abort();			\
    if ((mask & dst_ref) != dst2) abort();
#endif

#if AVX512F_LEN == 256
#undef CMP
#define CMP(imm, rel)					\
    dst_ref = 0;					\
    for (i = 0; i < 4; i++)				\
    {							\
      dst_ref = ((rel) << i) | dst_ref;			\
    }							\
    source1.x = _mm256_loadu_si256 ((__m256i*)s1);		\
    source2.x = _mm256_loadu_si256 ((__m256i*)s2);		\
    dst1 = _mm256_cmp_epi64_mask (source1.x, source2.x, imm);\
    dst2 = _mm256_mask_cmp_epi64_mask (mask, source1.x, source2.x, imm);\
    if (dst_ref != dst1) abort();			\
    if ((mask & dst_ref) != dst2) abort();
#endif

#if AVX512F_LEN == 128
#undef CMP
#define CMP(imm, rel)					\
    dst_ref = 0;					\
    for (i = 0; i < 2; i++)				\
    {							\
      dst_ref = ((rel) << i) | dst_ref;			\
    }							\
    source1.x = _mm_loadu_si128 ((__m128i*)s1);		\
    source2.x = _mm_loadu_si128 ((__m128i*)s2);		\
    dst1 = _mm_cmp_epi64_mask (source1.x, source2.x, imm);\
    dst2 = _mm_mask_cmp_epi64_mask (mask, source1.x, source2.x, imm);\
    if (dst_ref != dst1) abort();			\
    if ((mask & dst_ref) != dst2) abort();
#endif

void
TEST ()
{
    UNION_TYPE (AVX512F_LEN, i_d) source1, source2;
    MASK_TYPE dst1, dst2, dst_ref;
    MASK_TYPE mask = MASK_VALUE;
    long long s1[8] = {2134,  6678,  453, 54646,
		       231,  5674,  111, 23241};
    long long s2[8] = {41124, 6678, 8653,   856,
		       231,  4646,  111,   124};
    int i;

    CMP(0x00, s1[i] == s2[i]);
    CMP(0x01, s1[i] < s2[i]);
    CMP(0x02, s1[i] <= s2[i]);
    CMP(0x03, 0);
    CMP(0x04, s1[i] != s2[i]);
    CMP(0x05, s1[i] >= s2[i]);
    CMP(0x06, s1[i] > s2[i]);
    CMP(0x07, 1);
}
