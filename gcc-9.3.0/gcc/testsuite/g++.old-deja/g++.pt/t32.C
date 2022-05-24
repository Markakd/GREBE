// { dg-do assemble  }

template <class X> struct A {
  int fooo (int x);
  int x;
  inline int y () { return 3; }
  inline int z () { return 5; }
};

template <class Y> int A<Y>::fooo (int t) { return (this->*(x?&A<Y>::y : &A<Y>::z))() + t; }	// { dg-bogus "" } 

A<int> ai;

int frop () { return ai.fooo (100); }
