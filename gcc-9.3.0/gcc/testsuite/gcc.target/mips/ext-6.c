/* For MIPS64r2 use DEXT when ANDing with low-order bitmasks.  */
/* { dg-do compile } */
/* { dg-options "isa_rev>=2 -mgp64" } */
/* { dg-skip-if "code quality test" { *-*-* } { "-O0" } { "" } } */
/* { dg-final { scan-assembler "\tdext\t" } } */
/* { dg-final { scan-assembler-not "\tandi?\t" } } */

NOMIPS16 unsigned long long
f (unsigned long long i)
{
  return i & 0x7ffffffffff;
}
