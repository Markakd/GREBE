/* { dg-do run { target openacc_nvidia_accel_selected } } */
/* { dg-additional-options "-foffload=-fdump-tree-oaccdevlow" } */
/* { dg-set-target-env-var "GOMP_DEBUG" "1" } */

#include <stdlib.h>

#define N 1024

unsigned int a[N];
unsigned int b[N];
unsigned int c[N];
unsigned int n = N;

int
main (void)
{
  for (unsigned int i = 0; i < n; ++i)
    {
      a[i] = i % 3;
      b[i] = i % 5;
    }

#pragma acc parallel vector_length (128) copyin (a,b) copyout (c)
  {
#pragma acc loop worker
    for (unsigned int i = 0; i < 4; i++)
#pragma acc loop vector
      for (unsigned int j = 0; j < n / 4; j++)
	c[(i * N / 4) + j] = a[(i * N / 4) + j] + b[(i * N / 4) + j];
  }

  for (unsigned int i = 0; i < n; ++i)
    if (c[i] != (i % 3) + (i % 5))
      abort ();

  return 0;
}

/* { dg-final { scan-offload-tree-dump "__attribute__\\(\\(oacc function \\(1, 0, 128\\)" "oaccdevlow" } } */
/* { dg-output "nvptx_exec: kernel main\\\$_omp_fn\\\$0: launch gangs=1, workers=8, vectors=128" } */
