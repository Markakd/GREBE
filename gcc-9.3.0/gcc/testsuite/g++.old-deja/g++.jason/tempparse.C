// { dg-do assemble  }
/*
   PRMS Id: 3631
   Bug is: g++ mangles template class names in a way that it won't accept,
     and then tries to feed them to itself.
*/

template<class T>
struct A {
  A();
};

template<class T>
struct B : A<T> {
  B();
};				// { dg-bogus "" } B<C<char>>

template<class T>
struct C {
  C();
};

template<class T>
struct D {
  D();
  B<C<T> > p_f;
};

typedef D<char> Dummy;
