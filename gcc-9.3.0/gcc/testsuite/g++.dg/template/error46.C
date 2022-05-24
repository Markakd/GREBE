// PR c++/51230

template<int> struct A {}; 

template<int N> void foo(A<N>, A<N>); // { dg-message "template" }

void bar()
{
  foo(A<0>(), A<1>()); // { dg-error "no matching" }
}
// { dg-message "deduced conflicting values" "" { target *-*-* } 9 }
