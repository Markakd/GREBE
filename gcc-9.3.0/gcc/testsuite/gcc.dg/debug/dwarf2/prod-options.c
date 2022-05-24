/* Verify that the DW_AT_producer does not contain certain compiler options
   such as -fdebug-prefix-map=; this is undesirable since path names make
   the build not reproducible.  Other skipped options could be tested here
   as well.  */
/* { dg-do compile } */
/* { dg-options "-O2 -gdwarf -dA -fno-merge-debug-strings -fdebug-prefix-map=a=b" } */
/* { dg-final { scan-assembler "\"GNU C\[^\\n\\r\]+ DW_AT_producer" } } */
/* { dg-final { scan-assembler-not "debug-prefix-map" } } */

void func (void)
{
}
