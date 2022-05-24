/* { dg-do compile } */
/* This test requires widening_mul */
/* { dg-options "-march=vr5400 -mgp32 -fexpensive-optimizations" } */
/* { dg-skip-if "code quality test" { *-*-* } { "-O0" } { "" } } */
/* { dg-final { scan-assembler-times "\tmsacu\t\\\$0," 2 } } */

typedef unsigned int ui;
typedef unsigned long long ull;

NOMIPS16 ull
f1 (ui x, ui y, ull z)
{
  return z - (ull) y * x;
}

NOMIPS16 ull
f2 (ui x, ui y, ull z)
{
  ull t = (ull) x * y;
  int temp = 5;
  if (temp == 5)
    z -= t;
  return z;
}
