// { dg-do assemble  }
namespace A{
  enum foo{a,b,c};
}
using A::foo;
using A::b;
void g()
{
  foo x;
  x=b;
}
