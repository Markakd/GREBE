/* { dg-do compile } */
/* { dg-require-effective-target arm_cond_exec } */
/* { dg-options "-O2" } */

#define MAX(a, b) (a > b ? a : b)
int
foo (int a, int b, int c)
{
  return c - MAX (a, b);
}

/* { dg-final { scan-assembler-not "mov" } } */
