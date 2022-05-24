/* { dg-do compile } */
/* { dg-options "-O -fopenmp -fdump-tree-ompexp" } */

int
main()
{
#pragma omp parallel
    {;}
}

/* There should not be a GOMP_parallel_start call.  */
/* { dg-final { scan-tree-dump-times "GOMP_parallel_start" 0 "ompexp"} } */
