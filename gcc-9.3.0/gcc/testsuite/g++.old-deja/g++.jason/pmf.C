// { dg-do assemble  }
// PRMS Id: 4333
// Bug: g++ can't deal with casts to pointer to member function.

class A { };
typedef void (A::* pmf)();
void foo () { (pmf) 0; }
