/* { dg-do compile } */
/* { dg-options "-march=vr4130 -mfix-vr4130" } */
NOMIPS16 int foo (void) { int r; asm ("# foo" : "=l" (r)); return r; }
/* { dg-final { scan-assembler "\tmacc\t" } } */
