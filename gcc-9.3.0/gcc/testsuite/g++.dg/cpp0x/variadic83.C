// PR c++/31441
// { dg-do compile { target c++11 } }

template<typename> struct A;

template<typename... T> struct A<T...> { }; // { dg-error "" }

A<int> a;
