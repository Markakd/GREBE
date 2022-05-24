/* { dg-lto-options {{-O2 -DOPTIMIZE -flto -flto-partition=1to1} {-O0 -flto -flto-partition=1to1}} } */

extern void abort (void);
extern int foo (void);

int f (void)
{
  return 1;
}

extern inline int __attribute__ ((gnu_inline))
e_inline_baz (void)
{
  return 1 + f();
}

int
bar (void)
{
  return e_inline_baz ();
}

int
main ()
{
#ifdef OPTIMIZE
  if (bar () != 2 || foo () != 3)
    abort ();
#else
  if (bar () != 0 || foo () != 0)
    abort ();
#endif
  return 0;
}
