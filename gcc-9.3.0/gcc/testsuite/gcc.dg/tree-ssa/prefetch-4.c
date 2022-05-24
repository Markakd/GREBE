/* The loop rolls too little, hence the prefetching would not be useful.  */

/* { dg-do compile { target { i?86-*-* x86_64-*-* } } } */
/* { dg-options "-O2 -fprefetch-loop-arrays -march=amdfam10 -fdump-tree-optimized" } */

int xxx[20];

void foo (int n)
{
  int i;

  for (i = 0; i < n; i++)
    xxx[i] = i;
}

/* { dg-final { scan-tree-dump-times "prefetch" 0 "optimized" } } */
