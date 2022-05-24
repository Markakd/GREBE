/* Test whether traditional stringify works.  */
/* { dg-do run } */

#define foo(a, b) c="a"; d="b";

extern void abort ();
extern void exit (int);

int main ()
{
  char *c, *d;

  foo (p,q);
  if (c[0] != 'p' || d[0] != 'q')
    abort ();

  exit (0);
}
