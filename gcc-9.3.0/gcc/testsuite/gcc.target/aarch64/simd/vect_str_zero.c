/* { dg-do compile } */
/* { dg-options "-O1" } */

#include <arm_neon.h>

void
f (uint32x4_t *p)
{
  uint32x4_t x = { 0, 0, 0, 0};
  p[4] = x;

  /* { dg-final { scan-assembler "stp\txzr, xzr," } } */
}

void
g (float32x2_t *p)
{
  float32x2_t x = {0.0, 0.0};
  p[400] = x;

  /* { dg-final { scan-assembler "str\txzr, " } } */
}

/* { dg-final { scan-assembler-not "add\tx\[0-9\]\+, x0, \[0-9\]+" } } */
