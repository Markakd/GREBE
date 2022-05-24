/* { dg-do run } */
/* { dg-options "-std=gnu99 -msse2 -mpreferred-stack-boundary=4" } */
/* { dg-require-effective-target sse2 } */

#include "sse2-check.h"

#include <emmintrin.h>

#ifdef __x86_64__
# define PUSH "pushq %rsi"
# define POP "popq %rsi"
#else
# define PUSH "pushl %esi"
# define POP "popl %esi"
#endif

__m128i __attribute__ ((__noinline__))
vector_using_function ()
{
  volatile __m128i vx;	/* We want to force a vector-aligned store into the stack.  */
  vx = _mm_xor_si128 (vx, vx);
  return vx;
}
int __attribute__ ((__noinline__, __force_align_arg_pointer__))
self_aligning_function (int x, int y)
{
  __m128i ignored = vector_using_function ();
  return (x + y);
}
int g_1 = 20;
int g_2 = 22;

static void
sse2_test (void)
{
  int result;
  asm (PUSH);                  /* Misalign runtime stack.  */
  result = self_aligning_function (g_1, g_2);
  if (result != 42)
    abort ();
  asm (POP);
}
