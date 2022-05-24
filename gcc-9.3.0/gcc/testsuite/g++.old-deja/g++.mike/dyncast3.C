// { dg-do run { xfail sparc64-*-elf arm-*-pe**-* } }
// { dg-options "-fexceptions -w" }
// Ensure that the return type of dynamic_cast is the real type.

struct B {
  virtual int f() { }
};

struct D : public B {
  virtual int f() { }
  int i;
} od;

main() {
  B *b=&od;
  if (dynamic_cast<D*>(b)->i)
    return 1;
  return 0;
}
