// { dg-do assemble  }
// { dg-options "-Wno-deprecated" }

template <class T>
struct A
{
  typedef T A_Type;
};


template <class U>
struct B : public A<U>
{
};


template <class U>
struct C : public B<U>
{
  void Func(A_Type);  // { dg-error "has not been declared" } implicit typename
};


template <class U>
void C<U>::Func(A_Type) { // { dg-error "declared void" "void" } implicit typename
// { dg-error "not declared" "decl" { target *-*-* } .-1 }
}
