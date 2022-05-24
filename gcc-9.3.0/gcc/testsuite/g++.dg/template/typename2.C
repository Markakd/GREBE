// { dg-do compile }
// { dg-options "" }

// Copyright (C) 2001, 2003 Free Software Foundation, Inc.
// Contributed by Nathan Sidwell 21 Mar 2002 <nathan@codesourcery.com>

// PR 5507. Overzealous implicit typename warning

template<typename _CharT>
class __ctype_abstract_base
{
  typedef int mask;
};

template<typename _CharT>
class ctype : public __ctype_abstract_base<_CharT>
{
  typedef typename ctype::mask mask;
};

template<typename _CharT>
class ctype2 : public __ctype_abstract_base<_CharT>
{
  typedef mask mask; // { dg-error "does not name a type" "no type" }
  // { dg-message "note" "note" { target *-*-* } .-1 }
};
