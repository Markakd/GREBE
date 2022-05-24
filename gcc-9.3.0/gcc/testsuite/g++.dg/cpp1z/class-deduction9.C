// { dg-do compile { target c++17 } }

namespace N {
  template <class T>
  struct A
  {
    int i;
    A(...);
  };
}

template <class T>
N::A(T) -> N::A<T>;	  // { dg-error "should have been declared inside .N" }

namespace N {
  template <class T>
  A(T) -> A<T>;
}
