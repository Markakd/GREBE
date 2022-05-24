/* { dg-do compile { target { ! { nvptx*-*-* visium-*-* } } } } */
/* { dg-options "-O2 -fpatchable-function-entry=3,1" } */
/* { dg-additional-options "-fno-pie" { target sparc*-*-* } } */
/* { dg-final { scan-assembler-times "nop|NOP" 3 { target { ! { alpha*-*-* } } } } } */
/* { dg-final { scan-assembler-times "bis" 3 { target alpha*-*-* } } } */

extern int a;

/* Nothing declared must not mean anything.  */
int f3 (void);

/* F3 should get a default-sized NOP area.  */
int
__attribute__((noinline))
f3 (void)
{
  return 5*a;
}
