/* PR middle-end/39315  */
/* { dg-do compile } */
/* { dg-options "-O -msse2 -mtune=generic" } */
/* { dg-final { scan-assembler-not "movups" } } */
/* { dg-final { scan-assembler-not "movlps" } } */
/* { dg-final { scan-assembler-not "movhps" } } */
/* { dg-final { scan-assembler "movaps" } } */

typedef float __m128 __attribute__ ((__vector_size__ (16)));

extern void bar (__m128 *);

void
foo (__m128 *x)
{
  __m128 b = *x;
  bar (&b);
}
