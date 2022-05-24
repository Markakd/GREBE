// PR c++/43028
// { dg-do compile { target c++11 } }

#include <initializer_list>

struct string { string(std::initializer_list<char>) { } };

void f() {
  auto y =
  {
    string(Equation()) // { dg-error "12:'Equation' was not declared" }
  }; // { dg-error "unable to deduce" }
}
