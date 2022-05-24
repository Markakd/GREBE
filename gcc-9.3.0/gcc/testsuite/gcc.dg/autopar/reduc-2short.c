/* { dg-do compile } */
/* { dg-options "-O2 -ftree-parallelize-loops=4 -fdump-tree-parloops2-details -fdump-tree-optimized" } */

#include <stdarg.h>
#include <stdlib.h>

#define N 1600
#define DIFF 242

short b[N] = {1,3,6,9,12,15,18,21,24,27,30,33,36,39,42,45};
short c[N] = {1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

__attribute__ ((noinline))
void main1 (short x, short max_result, short min_result)
{
  int i;
  short diff = 2;
  short max = x;
  short min = x;

  for (i = 0; i < N; i++) {
    diff += (short)(b[i] - c[i]);
  }
  for (i = 0; i < N; i++) {
    max = max < c[i] ? c[i] : max;
  }

  for (i = 0; i < N; i++) {
    min = min > c[i] ? c[i] : min;
  }

  /* check results:  */
  if (diff != DIFF)
    abort ();
  if (max != max_result)
    abort ();
  if (min != min_result)
    abort ();
}

void __attribute__((noinline))
  __attribute__((optimize ("-ftree-parallelize-loops=0")))
init_arrays ()
 {
   int i;

   for (i=16; i<N; i++)
     {
       b[i] = 1;
       c[i] = 1;
     }
}

int main (void)
{ 
  init_arrays();
  main1 (100, 100, 1);
  main1 (0, 15, 0);
  return 0;
}

/* { dg-final { scan-tree-dump-times "Detected reduction" 2 "parloops2" } } */
/* { dg-final { scan-tree-dump-times "Detected reduction" 3 "parloops2" { xfail *-*-* } } } */

/* { dg-final { scan-tree-dump-times "SUCCESS: may be parallelized" 2 "parloops2" } } */
/* { dg-final { scan-tree-dump-times "SUCCESS: may be parallelized" 3 "parloops2" { xfail *-*-* } } } */
