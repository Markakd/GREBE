// { dg-do run { target i?86-*-* x86_64-*-* } }
// { dg-options "-fabi-version=0" }
// { dg-require-effective-target ilp32 }


struct A { 
  virtual void f() {}
  int f1 : 1; 
};

struct B : public A {
  int f2 : 31;
  int f3 : 4; 
  int f4 : 3;
};

int main ()
{
  if (sizeof (B) != 16)
    return 1;
}
  
