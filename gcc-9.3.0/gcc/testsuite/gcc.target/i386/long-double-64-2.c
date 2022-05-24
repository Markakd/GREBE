/* { dg-do compile { target { *-*-linux* && ia32 } } } */
/* { dg-options "-O2 -mbionic" } */

long double
foo (long double x)
{
  return x * x;
}

/* { dg-final { scan-assembler-not "fldt" } } */
/* { dg-final { scan-assembler-not "call\[\\t \]*_?__multf3" } } */
