/* PR target/22585 */
/* Testcase reduced by Volker Reichelt */
/* { dg-do compile } */
/* { dg-options "-march=i386 -O -ffast-math" } */
/* { dg-require-effective-target ia32 } */

int
foo (long double d, int i)
{
  if (d == (long double) i)
    return 1;
}
