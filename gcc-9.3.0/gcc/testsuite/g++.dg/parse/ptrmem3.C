// Copyright (C) 2005 Free Software Foundation, Inc.
// Contributed by Nathan Sidwell 14 Feb 2005 <nathan@codesourcery.com>

// Origin: Volker Reichelt <reichelt@gcc.gnu.org>
// Bug 19895: ICE on invalid


template<typename> struct A
{
  int A<0>::* p; // { dg-error "(type/value mismatch)|(expected)" }
};
