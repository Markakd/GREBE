// PR c++/51370

struct A
{
  template<typename> void foo() {}
};

template<void (A::*)()> struct B {};

template<int> struct C
{
  B<&A::foo<int int> > b; // { dg-error "declaration|type" }
};

C<0> c;

// { dg-prune-output "could not convert" }
