// { dg-do compile { target c++11 } }

struct A
{
  int i;
  template <class T> A(T t);
};

struct C
{
  C() = delete;			// { dg-message "declared here" }
};

struct B: A, C
{
  using A::A;			// { dg-error "C::C" }
};

int main()
{
  B b(24);			// { dg-error "B::B" }
}
