// { dg-do assemble  }

template <class T> struct A {};
template <class T> struct B : A<B<T> > {};

B<int> x;
