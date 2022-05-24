// PR c++/49921
// { dg-do compile { target c++11 } }

struct Local
{
  void f();
};

Local *l;
void (Local::*ptr)();
decltype((l->*ptr)) i;	       // { dg-error "member function" }

// { dg-prune-output "invalid type in declaration" }
