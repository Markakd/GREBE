// { dg-do assemble  }
// GROUPS passed gb scope
struct c {
  class t { };
  struct d {
    void foo (t &);
  };
};

void c::d::foo (t & x) { }
