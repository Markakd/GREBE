// Test for constant initialization of class with vtable
// { dg-options "-save-temps" }
// { dg-final { scan-assembler-not "static_initialization" } }
// { dg-do run { target c++11 } }

int r = 1;
// implicit default constructor for A and B is constexpr
struct A { virtual void f() {} };
struct B: A { virtual void f() { r = 0; } };

B b;

int main()
{
  b.f();
  return r;
}
