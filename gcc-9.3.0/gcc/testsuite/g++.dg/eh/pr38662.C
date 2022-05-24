// { dg-do compile { target { { i?86-*-* x86_64-*-* } && ia32 } } }
class E { };

class T {
  int foo(bool a)
#if __cplusplus <= 201402L
  throw (E)			// { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } }
#endif
  __attribute__((regparm(1)));
  int bar(bool b) __attribute__((regparm(1)));
};

int T::bar(bool b)
{
  return (b ? 1 : 2);
}

