// { dg-do assemble  }
// GROUPS passed static
class A { public: int a; };// { dg-message "" } .*
void foo7 () { A::a = 3; }// { dg-error "" } .*
