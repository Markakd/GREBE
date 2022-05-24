// PR c++/23266
// Origin: Volker Reichelt  <reichelt@igpm.rwth-aachen.de>
// { dg-do compile }

void foo0() = 0;                   // { dg-error "6:function .void foo0\\(\\). is initialized like a variable" }
virtual void foo1() = 0;           // { dg-error "1:'virtual' outside class" }
// { dg-error "14:function .void foo1\\(\\). is initialized like a variable" "" { target *-*-* } .-1 }
struct A
{
  void foo2() = 0;                 // { dg-error "8:initializer specified for non-virtual method" }
  static void foo3() = 0;          // { dg-error "15:initializer specified for static member function" }
  virtual static void foo4() = 0;  // { dg-error "both 'virtual' and 'static'" }
  virtual void foo5() = 0;         // { dg-error "base class" }
};

struct B : A
{
  static void foo5() = 0;          // { dg-error "15:initializer specified for static member function" }
// { dg-error "declared" "" { target *-*-* } .-1 }  
};
