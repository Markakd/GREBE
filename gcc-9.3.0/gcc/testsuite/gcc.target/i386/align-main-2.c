/* Test for stack alignment when PREFERRED_STACK_BOUNDARY > alignment
   of local variable.  */
/* { dg-do compile } */
/* { dg-options "-O2 -mpreferred-stack-boundary=6 -mincoming-stack-boundary=6" } */
/* { dg-final { scan-assembler "and\[lq\]?\[\\t \]*\\$-64,\[\\t \]*%\[re\]?sp" } } */
/* { dg-final { scan-assembler-not "and\[lq\]?\[\\t \]*\\$-128,\[\\t \]*%\[re\]?sp" } } */
/* { dg-skip-if "Options about stack-boundary aren't support" { x86_64-*-mingw* } } */
#include <stddef.h>

#define ALIGNMENT 32
typedef int aligned __attribute__((aligned(ALIGNMENT)));
extern void abort(void);

__attribute__ ((noinline))
void check(void * a)
{
  if (((ptrdiff_t)a & (ALIGNMENT-1)) != 0)
    abort();
}

int main()
{
  aligned a = 1;
  check(&a);
  return 0;
}
