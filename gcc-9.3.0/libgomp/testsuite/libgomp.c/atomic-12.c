/* { dg-do run } */

extern void abort (void);
_Bool v, x1, x2, x3, x4, x5, x6;

void
foo (void)
{
  #pragma omp atomic capture
  v = ++x1;
  if (!v)
    abort ();
  #pragma omp atomic capture
  v = x2++;
  if (v)
    abort ();
  #pragma omp atomic capture
  v = --x3;
  if (v)
    abort ();
  #pragma omp atomic capture
  v = x4--;
  if (!v)
    abort ();
  #pragma omp atomic capture
  { v = x5; x5 |= 1; }
  if (v)
    abort ();
  #pragma omp atomic capture
  { x6 |= 1; v = x6; }
  if (!v)
    abort ();
}

void
bar (void)
{
  #pragma omp atomic write
  x1 = 0;
  #pragma omp atomic write
  x2 = 0;
  #pragma omp atomic write
  x3 = 1;
  #pragma omp atomic write
  x4 = 1;
  #pragma omp atomic capture
  { ++x1; v = x1; }
  if (!v)
    abort ();
  #pragma omp atomic capture
  { v = x2; x2++; }
  if (v)
    abort ();
  #pragma omp atomic capture
  { --x3; v = x3; }
  if (v)
    abort ();
  #pragma omp atomic capture
  { v = x4; x4--; }
  if (!v)
    abort ();
  #pragma omp atomic write
  x1 = 0;
  #pragma omp atomic write
  x2 = 0;
  #pragma omp atomic write
  x3 = 1;
  #pragma omp atomic write
  x4 = 1;
  #pragma omp atomic capture
  { x1++; v = x1; }
  if (!v)
    abort ();
  #pragma omp atomic capture
  { v = x2; ++x2; }
  if (v)
    abort ();
  #pragma omp atomic capture
  { x3--; v = x3; }
  if (v)
    abort ();
  #pragma omp atomic capture
  { v = x4; --x4; }
  if (!v)
    abort ();
}

int
main ()
{
  #pragma omp atomic write
  x3 = 1;
  #pragma omp atomic write
  x4 = 1;
  foo ();
  bar ();
  return 0;
}
