// PR c++/46807
// { dg-do compile { target c++11 } }
// In C++98/03, B::B(const B&) is trivial because A::A(const A&) is trivial,
// even though doing overload resolution would mean calling the template
// constructor.  In C++11, we do overload resolution to determine triviality.

struct A
{
  A() {}
private:
  template <class T> A(T&);	// { dg-message "private" }
};

struct B			// { dg-error "implicitly deleted|this context" }
{
  mutable A a;
};

int main()
{
  B b;
  B b2(b);			// { dg-error "deleted" }
}
