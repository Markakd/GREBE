// { dg-do assemble  }
// GROUPS passed templates membertemplates
template <class T>
struct S
{
  template <class U>
  void foo(U);
};

void f()
{
  S<int> s;
}
