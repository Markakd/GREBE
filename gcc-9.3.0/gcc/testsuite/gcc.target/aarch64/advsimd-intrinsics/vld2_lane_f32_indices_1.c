#include <arm_neon.h>

/* { dg-do compile } */
/* { dg-skip-if "" { *-*-* } { "-fno-fat-lto-objects" } } */

float32x2x2_t
f_vld2_lane_f32 (float32_t * p, float32x2x2_t v)
{
  float32x2x2_t res;
  /* { dg-error "lane 2 out of range 0 - 1" "" { target *-*-* } 0 } */
  res = vld2_lane_f32 (p, v, 2);
  /* { dg-error "lane -1 out of range 0 - 1" "" { target *-*-* } 0 } */
  res = vld2_lane_f32 (p, v, -1);
  return res;
}
