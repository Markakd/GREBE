/* { dg-do compile } */
/* { dg-options "-O2 -funroll-loops -fdump-tree-cunroll-details" } */

__attribute__ ((pure))
int bla(int);

int foo(void)
{
  int i;
  int sum = 0;

  /* This loop used to appear to be too large for unrolling.  */
  for (i = 0; i < 4; i++)
    {
      sum += bla (i);
      sum += bla (2*i);
      sum += bla (3*i);
      sum += bla (4*i);
      sum += bla (5*i);
      sum += bla (6*i);
      sum += bla (7*i);
      sum += bla (8*i);
    }
  return sum;
}

/* { dg-final { scan-tree-dump-times "loop with 3 iterations completely unrolled" 1 "cunroll" } } */
