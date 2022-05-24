// Copyright (C) 2005 Free Software Foundation, Inc.
// Contributed by Nathan Sidwell 13 Jun 2005 <nathan@codesourcery.com>

// Origin:   Ivan Godard <igodard@pacbell.net>
// Bug 20789: ICE on invalid

template<typename> struct A;

template<int> struct B {};

template<typename T> struct C
{
  static const int i = A<T>::i;  // { dg-error "incomplete" }
  static const int j = i;
  B<j> b;
};

C<int> c;

int i = C<int>::i;
int j = C<int>::j;
