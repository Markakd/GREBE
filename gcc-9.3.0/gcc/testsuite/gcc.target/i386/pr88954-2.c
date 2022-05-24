/* { dg-do compile { target *-*-linux* } } */
/* { dg-options "-O2 -fno-pic -fplt" } */

extern void bar (void) __attribute__((noplt));
extern void *p;

void
foo (void)
{
  p = &bar;
}

/* { dg-final { scan-assembler "mov\(l|q\)\[ \t\]*bar@GOTPCREL" { target { ! ia32 } } } } */
/* { dg-final { scan-assembler "movl\[ \t\]*bar@GOT," { target { ia32 && got32x_reloc } } } } */
/* { dg-final { scan-assembler-not "mov\(l|q\)\[ \t\]*\\\$bar," { target { ! ia32 } } } } */
/* { dg-final { scan-assembler-not "mov\(l|q\)\[ \t\]*\\\$bar," { target { ia32 && got32x_reloc } } } } */
