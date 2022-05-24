// { dg-do assemble  }
// { dg-options "-Wno-pmf-conversions" }
// Testcase for cast of bound pointer to member function.

struct A {
  int f ();
};

typedef int (*fptr)(A *);
typedef void* vptr;
typedef int (A::*pmf)();

void foo (A* ap, pmf fp, int A::* ip)
{
  fptr p;
  vptr q;
  A a;

  p = (fptr)(ap->*fp);
  p = (fptr)(ap->*fp);
  p = (fptr)(ap->*(&A::f));
  p = (fptr)(a.*fp);
  p = (fptr)(a.*(&A::f));

  q = (vptr)(ap->*fp);
  q = (vptr)(ap->*(&A::f));
  q = (vptr)(a.*fp);
  q = (vptr)(a.*(&A::f));
}
