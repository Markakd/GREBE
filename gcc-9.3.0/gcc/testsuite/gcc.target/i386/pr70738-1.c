/* { dg-do compile { target { ! ia32 } } } */
/* { dg-options "-msse2 -mgeneral-regs-only" } */

typedef int int32x2_t __attribute__ ((__vector_size__ ((8))));

int32x2_t test (int32x2_t a, int32x2_t b)
{ /* { dg-error "SSE register return with SSE disabled" } */
  return a + b;
}
