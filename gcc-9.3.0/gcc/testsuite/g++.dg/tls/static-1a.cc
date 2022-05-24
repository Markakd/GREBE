// { dg-do run }
// { dg-options "-O2" }
// { dg-require-effective-target tls_runtime }
// { dg-add-options tls }
// { dg-additional-sources "static-1a.cc" }

struct A
{
  static __thread int i;
};

int
test ()
{
  if (A::i != 8)
    return 1;

  A::i = 17;
  return 0;
}
