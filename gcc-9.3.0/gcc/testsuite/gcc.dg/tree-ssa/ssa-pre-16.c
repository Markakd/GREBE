/* { dg-do compile } */ 
/* { dg-options "-O2 -fdump-tree-pre-stats -std=c99 -fno-tree-loop-im" } */
int foo(int k, int *x)
{
  int j=0;
  int res = 0;
  /* We should pull res = *x all the way out of the do-while */
  do {
    for (int n=0;n<3;++n);
    res = *x;
  }  while (++j<k);
  return res;
}
/* { dg-final { scan-tree-dump-times "Eliminated: 1" 1 "pre"} } */
