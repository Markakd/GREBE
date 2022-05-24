// { dg-do run { target i?86-*-* x86_64-*-* } }
// { dg-require-effective-target ilp32 }
// { dg-options "-fabi-version=0 -w" }

struct E {};
struct E2 : public E {};

struct A {
  int i;
};

struct B {
  int j;
};

struct C :
  public E, 
  public A, 
  public E2, 
  virtual public B {
};

C c;

int main () {
  if (((char*)(B*)&c - (char*)&c) != 8)
    return 1;
}
