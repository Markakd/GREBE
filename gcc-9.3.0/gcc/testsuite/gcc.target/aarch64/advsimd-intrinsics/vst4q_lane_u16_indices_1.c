#include <arm_neon.h>

/* { dg-do compile } */
/* { dg-skip-if "" { *-*-* } { "-fno-fat-lto-objects" } } */

void
f_vst4q_lane_u16 (uint16_t * p, uint16x8x4_t v)
{
  /* { dg-error "lane 8 out of range 0 - 7" "" { target *-*-* } 0 } */
  vst4q_lane_u16 (p, v, 8);
  /* { dg-error "lane -1 out of range 0 - 7" "" { target *-*-* } 0 } */
  vst4q_lane_u16 (p, v, -1);
  return;
}
