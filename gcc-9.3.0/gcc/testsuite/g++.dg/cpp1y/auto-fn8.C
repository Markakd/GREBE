// { dg-do compile { target c++14 } }

auto f() { return 42; }		// { dg-message "old declaration .auto" }
auto f();			// OK
int f();			// { dg-error "new declaration" }

template <class T> auto f(T t) { return t; }
template <class T> T f(T t);

int main()
{
  f(42);			// { dg-error "ambiguous" }
}
