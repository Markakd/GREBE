// Copyright (C) 2015-2019 Free Software Foundation, Inc.
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

// { dg-do compile { target c++14 } }

#include <experimental/numeric>

using std::experimental::fundamentals_v2::gcd;

static_assert( gcd(1071, 462) == 21, "" );
static_assert( gcd(2000, 20) == 20, "" );
static_assert( gcd(2011, 17) == 1, "GCD of two primes is 1" );
static_assert( gcd(200, 200) == 200, "GCD of equal numbers is that number" );
static_assert( gcd(0, 13) == 13, "GCD of any number and 0 is that number" );
static_assert( gcd(29, 0) == 29, "GCD of any number and 0 is that number" );
static_assert( gcd(0, 0) == 0, "" );

static_assert(gcd(1u, 2) == 1, "unsigned and signed");
static_assert(gcd(3, 4u) == 1, "signed and unsigned");
static_assert(gcd(5u, 6u) == 1, "unsigned and unsigned");
