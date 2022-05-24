/* { dg-do compile } */
/* { dg-options "-O2 -ftree-parallelize-loops=4 -fdump-tree-parloops2-details -fdump-tree-optimized -fno-partial-inlining" } */

#include <stdio.h>
#define MB 100
#define NA 450
#define MA 400

int T[MA][MB],A[MA][NA],B[MB][NA];
void __attribute__((noinline))
MRTRBR(int MA_1, int NA_1, int MB_1)
{
  int i,j, t,k;

  /* At the moment we are not able to hoist the loop headers out of the loop
     nest. 
     Partial inlining needs to be disabled so we do not optimize this out
     of the function body.  */
  if (MA_1 < 4 || NA_1 < 4 || MB_1 < 4)
    return;

  /* The outer most loop is not parallel because for different k's there
     is write-write dependency for T[i][j].  */
  
  /* The innermost loop doesn't get parallelized due to low number of 
     iterations.  */

  for (k = 3; k < NA_1; k++)
    for (i = 3; i < MA_1; i++)
      for (j = 3; j < MB_1; j++)
	{
	  t = T[i][j];
	  T[i][j] = t+2+A[i][k]*B[j][k];
	}
}
void main ()
{
  int j,i;
  
  for (i = 3; i < MA; i++)
    for (j = 3; j < MB; j++)
      {
	__asm__ volatile ("" : : : "memory");
	T[i][j] = (i>j?i:j);
      }
  
  MRTRBR (MA,NA,MB);
  
  for (i = MA-1; i < MA; i++)
    for (j = MB-10; j < MB; j++)
      printf ("i %d j %d T[i][j] = %d\n",i,j,T[i][j]);
}


/* Check that the outer most loop doesn't get parallelized.  */

/* { dg-final { scan-tree-dump-times "SUCCESS: may be parallelized" 1 "parloops2" } } */
/* { dg-final { scan-tree-dump-times "__builtin_GOMP_parallel" 1 "optimized" } } */
