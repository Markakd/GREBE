// { dg-do link { target c++11 } }

struct S {};

struct T
{
  operator S() { return S(); }
};

struct U
{
  operator S&() { return *static_cast<S*>(0); }
};

void f(const S&);
void f(S&&) {}

void g(const S&) {}
void g(S&&);

int main()
{
  T t;
  f(t);

  U u;
  g(u);
}
