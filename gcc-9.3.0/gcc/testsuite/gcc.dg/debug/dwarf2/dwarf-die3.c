/* Verify that extern inline function never actually inlined has no abstract DIE.  */
/* { dg-do compile } */
/* { dg-options "-O0 -gdwarf -dA -fgnu89-inline" } */
/* { dg-final { scan-assembler-not "DW_AT_inline" } } */
extern inline int t()
{
}
int (*q)()=t;
int t()
{
}
