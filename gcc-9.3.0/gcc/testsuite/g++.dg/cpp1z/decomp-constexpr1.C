// Test for reference address comparison in constant expression.
// { dg-do compile { target c++17 } }

int i[2];
struct A { int i, j; } a;

void f()
{
  {
    auto& [ x, y ] = i;
    static_assert (&x == &i[0]);
  }

  {
    auto& [ x, y ] = a;
    static_assert (&x == &a.i && &y != &a.i);
  }
}
