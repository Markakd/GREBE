/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-pre-stats" } */
typedef int type[2];
int foo(type *a, int argc)
{
  type c = {0, 1};
  int d, e;

  /* Should be able to eliminate the second load of *a and the add of zero
     along the main path. */
  d = (*a)[0];
  if (argc)
    {
      a = &c;
    }
  e = (*a)[0];
  return d + e;
}
/* { dg-final { scan-tree-dump-times "Eliminated: 2" 1 "pre"} } */
