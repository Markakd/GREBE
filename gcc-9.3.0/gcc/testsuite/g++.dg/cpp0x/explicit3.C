// Test for "contextually converted to bool"
// { dg-do compile { target c++11 } }

struct A
{
  explicit operator bool();
};

void f (bool);

struct B
{
  bool b;
};

struct C
{
  operator int();
};

struct D
{
  operator int();
};

int main()
{
  A a; C c; D d;
  // These contexts use an explicit bool conversion.
  if (a) {}
  for (; a; ) {}
  do {} while (a);
  while (a) {}
  a ? 1 : 0;
  a || true;
  a && true;
  !a;

  a ? c : 1;
  a ? c : d;

  // These do not.
  switch (a); 			// { dg-error "" }
  bool b = a;			// { dg-error "" }
  f(a);				// { dg-error "" }
  B b2 = { a };			// { dg-error "" }
  a + true;			// { dg-error "5:no match" }
  b ? a : true;			// { dg-error "5:?:" }
  a ? a : true;			// { dg-error "5:?:" }
}
