// { dg-do assemble  }
// GROUPS passed niklas nested-types
struct X {
struct A { A (int); };
struct B : A { B (int a) : A (a) {} };
};
