// { dg-do compile { target c++11 } }
template<typename... T> int foo()
{
  typename T::X x; // { dg-error "parameter packs|T" }
  return x;
}

void bar()
{
  foo<int>();
}
