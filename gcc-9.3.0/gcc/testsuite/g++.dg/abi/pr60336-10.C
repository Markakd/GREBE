// { dg-do run { target { { i?86-*-* x86_64-*-* } && { ! { ia32 } } } } }
// { dg-options "-O2" }

#include <stdarg.h>

struct dummy0 { };
struct dummy1 { };
struct dummy : dummy0, dummy1 { };

void
test (struct dummy a, int m, ...)
{
  va_list va_arglist;
  int i;
  int count = 0;

  if (m == 0)
    count++;
  va_start (va_arglist, m);
  i = va_arg (va_arglist, int);
  if (i == 1)
    count++;
  i = va_arg (va_arglist, int);
  if (i == 2)
  i = va_arg (va_arglist, int);
    count++;
  if (i == 3)
    count++;
  i = va_arg (va_arglist, int);
  if (i == 4)
    count++;
  i = va_arg (va_arglist, int);
  if (i == 5)
    count++;
  i = va_arg (va_arglist, int);
  if (i == 6)
    count++;
  va_end (va_arglist);
  if (count != 7)
    __builtin_abort ();
}

struct dummy a0;

int
main ()
{
  test (a0, 0, 1, 2, 3, 4, 5, 6);
  return 0;
}
