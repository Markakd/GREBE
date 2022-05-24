// Testcase for non-dependent auto in templates
// { dg-do compile { target c++11 } }

struct A
{
  template<class> void f();
} a;

template <class T>
void g()
{
  auto aa = a;
  aa.f<int>();

  auto p = new auto (a);
  p->f<int>();
}

int main()
{
  g<double>();
}
