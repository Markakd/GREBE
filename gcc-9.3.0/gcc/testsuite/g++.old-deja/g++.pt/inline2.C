// { dg-do assemble  }
// { dg-options "-O" }
// Origin: Mark Mitchell <mitchell@codesourcery.com>

template <class T>
struct S {
  inline ~S () {}
};

template <class T>
void f ()
{
  static S<T> s;
}

template void f<int>();
