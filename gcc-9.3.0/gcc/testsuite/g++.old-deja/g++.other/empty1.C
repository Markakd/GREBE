// { dg-do run  }
// Origin: Mark Mitchell <mark@codesourcery.com>
// This test case checks that the return value optimization works for
// empty classes.

// PR c++/5995

extern "C" void abort();
extern "C" int printf (const char *, ...);

int i;

struct A;

struct A* as[10];

struct A {
  A () { as[i++] = this; }
  A (const A&) { as[i++] = this; }
  ~A() { if (i == 0 || as[--i] != this) abort(); }
};

A f() { return A(); }

int main ()
{
  A a (f ());
}
