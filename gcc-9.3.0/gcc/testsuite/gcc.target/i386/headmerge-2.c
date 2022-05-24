/* { dg-do compile }  */
/* { dg-require-effective-target nonpic } */
/* { dg-options "-O2" }  */
/* { dg-final { scan-assembler-times "\\\$120|, 120" 1 } } */

extern void foo1 (int);
extern void foo2 (int);
extern void foo3 (int);
extern void foo4 (int);
extern void foo5 (int);
extern void foo6 (int);

void t (int x, int y)
{
  switch (y)
    {
    case 1:
      foo1 (120);
      break;
    case 5:
      foo2 (120);
      break;
    case 7:
      foo3 (120);
      break;
    case 10:
      foo4 (120);
      break;
    case 13:
      foo5 (120);
      break;
    default:
      foo6 (120);
      break;
    }
}
