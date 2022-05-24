// { dg-do run  }
// GROUPS passed sizeof
// ARM $5.3.2

extern "C" int printf (const char *, ...);

class foo {};

int
main ()
{
  // The size of any class or class object is larger than zero.
  int i = sizeof (foo);
  if (i > 0)
    printf ("PASS\n");
  else
    { printf ("FAIL\n"); return 1; }
}
