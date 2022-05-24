/* Test vqabs_s64 intrinsics work correctly.  */
/* { dg-do run } */
/* { dg-options "--save-temps" } */

#include <arm_neon.h>

extern void abort (void);

int __attribute__ ((noinline))
test_vqabs_s64 (int64x1_t passed, int64_t expected)
{
  return vget_lane_s64 (vqabs_s64 (passed), 0) != expected;
}

int __attribute__ ((noinline))
test_vqabsd_s64 (int64_t passed, int64_t expected)
{
  return vqabsd_s64 (passed) != expected;
}

/* { dg-final { scan-assembler-times "sqabs\\td\[0-9\]+, d\[0-9\]+" 2 } } */

int
main (int argc, char **argv)
{
  /* Basic test.  */
  if (test_vqabs_s64 (vcreate_s64 (-1), 1))
    abort ();
  if (test_vqabsd_s64 (-1, 1))
    abort ();

  /* Getting absolute value of min int64_t.
     Note, exact result cannot be represented in int64_t,
     so max int64_t is expected.  */
  if (test_vqabs_s64 (vcreate_s64 (0x8000000000000000), 0x7fffffffffffffff))
    abort ();
  if (test_vqabsd_s64 (0x8000000000000000, 0x7fffffffffffffff))
    abort ();

  /* Another input that gets max int64_t.  */
  if (test_vqabs_s64 (vcreate_s64 (0x8000000000000001), 0x7fffffffffffffff))
    abort ();
  if (test_vqabsd_s64 (0x8000000000000001, 0x7fffffffffffffff))
    abort ();

  /* Checking that large positive numbers stay the same.  */
  if (test_vqabs_s64 (vcreate_s64 (0x7fffffffffffffff), 0x7fffffffffffffff))
    abort ();
  if (test_vqabsd_s64 (0x7fffffffffffffff, 0x7fffffffffffffff))
    abort ();

  return 0;
}
