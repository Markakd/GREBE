/* { dg-do compile } */
/* { dg-options "-O2 -ftree-parallelize-loops=4 -fdump-tree-parloops2-details -fdump-tree-optimized" } */

void abort (void);

int x[500][500];
int y[500];
int g_sum=0;

__attribute__((noinline))
void init (int i, int j)
{
  x[i][j]=1;
}

__attribute__((noinline))
void parloop (int N)
{
  int i, j;
  int sum;

  /* Inner cycle is currently not supported, outer loop is not 
     parallelized.  Inner reduction is detected, inner loop is 
     parallelized.  */
  for (i = 0; i < N; i++)
  {
    sum = 0;
    for (j = 0; j < N; j++)
      sum += x[i][j];
    y[i]=sum;
  }
  g_sum = sum;
}

int main(void)
{
  int i,j;
  for (i = 0; i < 500; i++) 
    for (j = 0; j < 500; j++)
      init(i, j);
  
  parloop(500);

  return 0;
}

/* { dg-final { scan-tree-dump-times "parallelizing outer loop" 1 "parloops2" { xfail *-*-* } } } */
/* { dg-final { scan-tree-dump-times "loopfn" 4 "optimized" { xfail *-*-* } } } */
