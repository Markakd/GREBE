/* { dg-do run } */
/* { dg-options "-O3 --save-temps" } */

#include <arm_neon.h>

#define DELTA 0.0001

extern double fabs (double);

extern void abort (void);

#define TEST_VMLS(q1, q2, size, in1_lanes, in2_lanes)			\
static void								\
test_vfms##q1##_lane##q2##_f##size (float##size##_t * res,		\
				   const float##size##_t *in1,		\
				   const float##size##_t *in2)		\
{									\
  float##size##x##in1_lanes##_t a = vld1##q1##_f##size (res);		\
  float##size##x##in1_lanes##_t b = vld1##q1##_f##size (in1);		\
  float##size##x##in2_lanes##_t c;					\
  if (in2_lanes > 1)							\
    {									\
      c = vld1##q2##_f##size (in2);					\
      a = vfms##q1##_lane##q2##_f##size (a, b, c, 1);			\
    }									\
  else									\
    {									\
      c = vld1##q2##_f##size (in2 + 1);					\
      a = vfms##q1##_lane##q2##_f##size (a, b, c, 0);			\
    }									\
  vst1##q1##_f##size (res, a);						\
}

#define BUILD_VARS(width, n_lanes, n_half_lanes)		\
TEST_VMLS ( ,  , width, n_half_lanes, n_half_lanes)		\
TEST_VMLS (q,  , width, n_lanes, n_half_lanes)			\
TEST_VMLS ( , q, width, n_half_lanes, n_lanes)			\
TEST_VMLS (q, q, width, n_lanes, n_lanes)			\

BUILD_VARS (32, 4, 2)
BUILD_VARS (64, 2, 1)

#define POOL2 {0.0, 1.0}
#define POOL4 {0.0, 1.0, 2.0, 3.0}
#define EMPTY2 {0.0, 0.0}
#define EMPTY4 {0.0, 0.0, 0.0, 0.0}

#define BUILD_TEST(size, lanes)					\
static void							\
test_f##size (void)						\
{								\
  int i;							\
  float##size##_t pool[lanes] = POOL##lanes;			\
  float##size##_t res[lanes] = EMPTY##lanes;			\
  float##size##_t res2[lanes] = EMPTY##lanes;			\
  float##size##_t res3[lanes] = EMPTY##lanes;			\
  float##size##_t res4[lanes] = EMPTY##lanes;			\
								\
  /* Forecfully avoid optimization.  */				\
  asm volatile ("" : : : "memory");				\
  test_vfms_lane_f##size (res, pool, pool);			\
  asm volatile ("" : :"Q" (res) : "memory");			\
  for (i = 0; i < lanes / 2; i++)				\
    if (fabs (res[i] + pool[i]) > DELTA)			\
      abort ();							\
								\
  /* Forecfully avoid optimization.  */				\
  test_vfmsq_lane_f##size (res2, pool, pool);			\
  asm volatile ("" : :"Q" (res2) : "memory");			\
  for (i = 0; i < lanes; i++)					\
    if (fabs (res2[i] + pool[i]) > DELTA)			\
      abort ();							\
								\
  /* Forecfully avoid optimization.  */				\
  test_vfms_laneq_f##size (res3, pool, pool);			\
  asm volatile ("" : :"Q" (res3) : "memory");			\
  for (i = 0; i < lanes / 2; i++)				\
    if (fabs (res3[i] + pool[i]) > DELTA)			\
      abort ();							\
								\
  /* Forecfully avoid optimization.  */				\
  test_vfmsq_laneq_f##size (res4, pool, pool);			\
  asm volatile ("" : :"Q" (res4) : "memory");			\
  for (i = 0; i < lanes; i++)					\
    if (fabs (res4[i] + pool[i]) > DELTA)			\
      abort ();							\
}

BUILD_TEST (32, 4)
BUILD_TEST (64, 2)

int
main (int argc, char **argv)
{
  test_f32 ();
  test_f64 ();
  return 0;
}

/* vfms_laneq_f32.
   vfms_lane_f32.  */
/* { dg-final { scan-assembler-times "fmls\\tv\[0-9\]+\.2s, v\[0-9\]+\.2s, v\[0-9\]+\.2s\\\[\[0-9\]+\\\]" 2 } } */

/* vfmsq_lane_f32.
   vfmsq_laneq_f32.  */
/* { dg-final { scan-assembler-times "fmls\\tv\[0-9\]+\.4s, v\[0-9\]+\.4s, v\[0-9\]+\.4s\\\[\[0-9\]+\\\]" 2 } } */

/* vfms_lane_f64.  */
/* { dg-final { scan-assembler-times "fmsub\\td\[0-9\]+\, d\[0-9\]+\, d\[0-9\]+\, d\[0-9\]+" 1 } } */

/* vfmsq_lane_f64.
   vfms_laneq_f64.
   vfmsq_laneq_f64.  */
/* { dg-final { scan-assembler-times "fmls\\tv\[0-9\]+\.2d, v\[0-9\]+\.2d, v\[0-9\]+\.2?d\\\[\[0-9\]+\\\]" 3 } } */


