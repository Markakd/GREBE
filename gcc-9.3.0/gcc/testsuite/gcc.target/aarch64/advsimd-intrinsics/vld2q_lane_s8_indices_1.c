#include <arm_neon.h>

/* { dg-do compile } */
/* { dg-skip-if "" { *-*-* } { "-fno-fat-lto-objects" } } */
/* { dg-skip-if "" { arm*-*-* } } */

int8x16x2_t
f_vld2q_lane_s8 (int8_t * p, int8x16x2_t v)
{
  int8x16x2_t res;
  /* { dg-error "lane 16 out of range 0 - 15" "" { target *-*-* } 0 } */
  res = vld2q_lane_s8 (p, v, 16);
  /* { dg-error "lane -1 out of range 0 - 15" "" { target *-*-* } 0 } */
  res = vld2q_lane_s8 (p, v, -1);
  return res;
}
