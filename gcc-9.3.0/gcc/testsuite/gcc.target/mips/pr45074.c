/* { dg-options "-mhard-float -mgp32" } */
register double g __asm__("$f20");

NOMIPS16 void
test (double a)
{
  g = -a;
}
