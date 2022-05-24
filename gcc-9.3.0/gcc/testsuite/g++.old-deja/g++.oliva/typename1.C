// { dg-do assemble  }

// Copyright (C) 1999 Free Software Foundation

// by Alexandre Oliva <oliva@dcc.unicamp.br>
// based on bug report by Nick Rasmussen <nick@jive.org>

template <class T> struct foo;

template <class T> struct bar {
  typedef int foo;
};

template <class T> struct baz {
  typedef bar<T>::foo foo; // { dg-error "need 'typename' before" "" { target c++17_down } }
};
