// { dg-do assemble  }
// Origin: Mark Mitchell <mark@codesourcery.com>

struct S {
  S();

  virtual int f() {
    new S[+f()];
    return 0;
  }
};
