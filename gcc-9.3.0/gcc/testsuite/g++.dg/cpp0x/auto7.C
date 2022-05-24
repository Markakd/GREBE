// PR c++/37965
// Negative test for auto
// { dg-do compile { target c++11 } }

auto i = 6;
auto j;			// { dg-error "has no initializer" }

template<int> struct A
{
  static auto k = 7;	// { dg-error "15:ISO C\\+\\+ forbids" }
  static auto l;	// { dg-error "has no initializer" }
  auto m;		// { dg-error "non-static data member declared" }
};
