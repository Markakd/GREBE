/* { dg-do compile } */
/* { dg-options "-O2" } */

#pragma GCC target ("movbe")

extern int x;

void
foo (int i)
{
  x = __builtin_bswap32 (i);
}

int
bar ()
{
  return __builtin_bswap32 (x);
}

/* { dg-final { scan-assembler-times "movbel\[ \t\]" 2 } } */
