// PR c++/85659
// { dg-do compile }

struct S { S (); ~S (); int s; };

void
foo (S &s)
{
  __asm volatile ("" : "+m,r" (s) : : "memory");
}
