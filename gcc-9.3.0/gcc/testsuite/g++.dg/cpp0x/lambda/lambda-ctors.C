// { dg-do run { target c++11 } }

struct A
{
  A() { }
  A(A&) { }
  A(A&&) { }
};

int main()
{
  A a;
  auto lam4 = [a]{};		// OK, implicit move ctor
  lam4();
  auto lam5 = lam4;		// OK, implicit copy ctor
  lam5();
}
