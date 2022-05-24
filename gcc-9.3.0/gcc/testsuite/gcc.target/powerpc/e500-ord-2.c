/* { dg-do compile { target powerpc*-*-eabi* } } */
/* { dg-options "-O -fno-trapping-math -fdump-rtl-final" } */

int isgreater (float f1, float f2)
{
  int r = (f1 > f2);
  return !r ?  -1 : 1;
}

int isgreaterequal (float f1, float f2)
{
  int r = (f1 >= f2);
  return !r ?  -1 : 1;
}

int isless (float f1, float f2)
{
  int r = (f1 < f2);
  return !r ?  -1 : 1;
}

int islessequal (float f1, float f2)
{
  int r = (f1 <= f2);
  return !r ?  -1 : 1;
}

/* { dg-final { scan-rtl-dump-not "__unordsf2" "final" } } */
