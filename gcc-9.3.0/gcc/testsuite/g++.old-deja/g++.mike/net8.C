// { dg-do assemble  }
// { dg-options "-pedantic-errors" }

class Base {
public:
  int foo;
};

class Derived : public Base {
public:
  int bar;
};

void func(Base&);			// { dg-message "argument 1" }

void func2(const Derived& d) {
  func(d);				// { dg-error "" }
}

void
foo (int& a)				// { dg-message "argument 1" }
{
}

int main ()
{
  int b;
  const int*const a = &b;
  *a = 10;				// { dg-error "read-only location" }
  foo (*a);				// { dg-error "qualifiers" }
  return 0;
}
