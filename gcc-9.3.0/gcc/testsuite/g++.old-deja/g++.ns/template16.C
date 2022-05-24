// { dg-do assemble  }
// Test that pushing into a namespace for a definition doesn't affect
// template instantiations.


namespace N {
  template <class T> void f () { }
  template <class T> struct A { friend void f<T>(); };
}

namespace M {
  struct B;
}

struct M::B: public N::A<int> { };
