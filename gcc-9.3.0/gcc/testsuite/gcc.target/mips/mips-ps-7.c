/* mips-ps-5.c with -mgp32 instead of -mgp64.  */
/* { dg-do compile } */
/* { dg-options "-mgp32 -mpaired-single -ftree-vectorize forbid_cpu=octeon.*" } */
/* { dg-skip-if "requires vectorization" { *-*-* } { "-O0" "-Os" } { "" } } */

extern float a[] __attribute__ ((aligned (8)));
extern float b[] __attribute__ ((aligned (8)));
extern float c[] __attribute__ ((aligned (8)));

NOMIPS16 void
foo (void)
{
  int i;
  for (i = 0; i < 16; i++)
    a[i] = b[i] == c[i] + 1 ? b[i] : c[i];
}

/* { dg-final { scan-assembler "\tadd\\.ps\t" } } */
/* { dg-final { scan-assembler "\tc\\.eq\\.ps\t" } } */
/* { dg-final { scan-assembler "\tmov\[tf\]\\.ps\t" } } */
