// { dg-do compile }

// Copyright (C) 2001 Free Software Foundation, Inc.
// Contributed by Nathan Sidwell 31 Dec 2001 <nathan@codesourcery.com>

// We'd tsubst a pointer to member reference

struct A {};

template <typename T> T A::* Foo (); // { dg-error "reference" }

void Baz ()
{
  Foo <int &> (); // { dg-error "no matching function" }
}
