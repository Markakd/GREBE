// PR c++/26572

template<int> void foo()
{
  struct A;                // { dg-message "declaration" }
  struct B : A {};         // { dg-error "invalid use of incomplete" }
}

template void foo<0>();
