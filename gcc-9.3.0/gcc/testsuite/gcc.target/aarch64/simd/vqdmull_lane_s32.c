/* Test the vqdmull_lane_s32 AArch64 SIMD intrinsic.  */

/* { dg-do compile } */
/* { dg-options "-save-temps -O3 -fno-inline" } */

#include "arm_neon.h"

int64x2_t
t_vqdmull_lane_s32 (int32x2_t a, int32x2_t b)
{
  return vqdmull_lane_s32 (a, b, 0);
}

/* { dg-final { scan-assembler-times "sqdmull\[ \t\]+\[vV\]\[0-9\]+\.2\[dD\], ?\[vV\]\[0-9\]+\.2\[sS\], ?\[vV\]\[0-9\]+\.\[sS\]\\\[0\\\]\n" 1 } } */
