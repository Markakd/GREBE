// Copyright (C) 2011-2019 Free Software Foundation, Inc.
//
// This file is part of the GNU ISO C++ Library.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the
// Free Software Foundation; either version 3, or (at your option)
// any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along
// with this library; see the file COPYING3.  If not see
// <http://www.gnu.org/licenses/>.

// { dg-do run { target c++11 } }

#include <functional>
#include <testsuite_hooks.h>

struct X
{
  int operator()() const { return 0; }
  int operator()() volatile { return 1; }
  int operator()() const volatile { return 2; }
  void operator()() { };
};

void test01()
{
  const auto b0 = std::bind(X());
  VERIFY( b0() == 0 );

#if __cplusplus <= 201402L
  volatile auto b1 = std::bind(X());
  VERIFY( b1() == 1 );

  const volatile auto b2 = std::bind(X());
  VERIFY( b2() == 2 );
#endif
}

int main()
{
  test01();
  return 0;
}
