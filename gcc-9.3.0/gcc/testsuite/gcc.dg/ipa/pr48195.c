/* { dg-do link } */
/* { dg-options "-O2 -flto --param partial-inlining-entry-probability=100" } */
/* { dg-require-effective-target lto } */

extern void abort(void);

int i;

void __attribute__ ((constructor))
c2 ()
{
  if (i)
    abort ();
}

void __attribute__ ((destructor))
d1 ()
{
  if (i)
    abort ();
}

void main ()
{
}
