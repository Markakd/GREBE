// { dg-do compile { target c++11 } }
// { dg-final { scan-assembler "_ZN1Q2V11fEv" } }
// { dg-final { scan-assembler "_ZN1Q2V11iE" } }

namespace Q {
  inline namespace V1 {
    extern int i;
    void f();
  }
}
int Q::i = 1;
void Q::f() { }
