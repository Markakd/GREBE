/* Functional tests for the function hotpatching feature.  */

/* { dg-do compile } */
/* { dg-options "-mzarch -mhotpatch=0,5" } */
/* { dg-skip-if "" { *-*-* } { "*" } { "-O*" } } */

#include <stdio.h>

void hp1(void)
{
  printf("hello, world!\n");
}

/* Check number of occurences of certain instructions.  */
/* { dg-final { scan-assembler-not "pre-label NOPs" } } */
/* { dg-final { scan-assembler "^\[^.\].*:\n.*post-label.*(5 halfwords).*\n\(\(.L.*:\n\)\|\(\[\[:space:\]\]*.cfi_.*\n\)\)*\[\[:space:\]\]*brcl\t0, 0" } } */
/* { dg-final { scan-assembler-not "nopr\t%r0" } } */
/* { dg-final { scan-assembler-times "nop\t0" 1 } } */
/* { dg-final { scan-assembler-times "brcl\t0, 0" 1 } } */
