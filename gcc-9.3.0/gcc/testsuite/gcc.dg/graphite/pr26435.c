/* { dg-do compile } */
/* { dg-options "-O2 -ftree-loop-linear" } */
/* { dg-require-effective-target size32plus } */

int foo(int *p, int n)
{
  int i, j, k = 0;

  /* This is a reduction: there is a scalar dependence that cannot be
     removed by rewriting IVs.  This code cannot and should not be
     transformed into a perfect loop.  */
  for (i = 0; i < 2; ++i, p += n)
    for (j = 0; j < 2; ++j)
      k += p[j];

  return k;
}
