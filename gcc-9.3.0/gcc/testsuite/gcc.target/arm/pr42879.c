/* { dg-require-effective-target arm_thumb2_ok } */
/* { dg-options "-mthumb -Os" }  */
/* { dg-final { scan-assembler "lsls" } } */

struct A
{
#ifdef __ARMEB__
  int dummy:31;
#endif
  int v:1;
};

int bar();
int foo(struct A* p)
{
  if (p->v)
    return 1;
  return bar();
}
