/* PR middle-end/37009 */
/* { dg-do compile { target { { ! *-*-darwin* } && ia32 } } } */
/* { dg-options "-w -msse2 -mpreferred-stack-boundary=2" } */

#include <emmintrin.h>

extern void bar (int *);

int
foo(__m128 x, __m128 y, __m128 z, int size)
{
  int __attribute((aligned(16))) xxx;

  xxx = 2;
  bar (&xxx);
  return size;
}

/* { dg-final { scan-assembler "andl\[\\t \]*\\$-16,\[\\t \]*%esp" } } */
