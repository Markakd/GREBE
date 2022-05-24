// { dg-do compile { target c++11 } }
struct A
{
  operator int();
};

template <typename... T> struct B : A
{
  using A::operator T; // { dg-error "parameter packs|T" }
};

B<int> b;
