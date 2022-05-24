// { dg-do run { target c++11 } }

// Copyright (C) 2016-2019 Free Software Foundation, Inc.
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

// 27.6.2.5.3 basic_ostream manipulator inserters

#include <sstream>

struct X {};
std::ostream& operator<<(std::ostream&, const X&) = delete;

struct Y {};
std::ostream& operator<<(std::ostream& os, const Y&) {return os;}
std::ostream& operator<<(std::ostream&& os, const Y&) {return os;}

struct Z{};

template <class T>
auto f(T&&) -> decltype(void(std::declval<std::ostream&>()
			     << std::declval<T&&>()),
			std::true_type());

std::false_type f(...);

template <class T>
auto g(T&&) -> decltype(void(std::declval<std::ostream&&>()
			     << std::declval<T&&>()),
			std::true_type());

std::false_type g(...);

void test01()
{
  Y y;
  std::ostringstream os;
  os << y;
  os << Y();
  std::ostringstream() << y;
  std::ostringstream() << Y();
  static_assert(!std::__is_insertable<std::ostream&, X&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&&, X&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&, X&&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&&, X&&>::value, "");
  static_assert(std::__is_insertable<std::ostream&, Y&>::value, "");
  static_assert(std::__is_insertable<std::ostream&&, Y&&>::value, "");
  static_assert(std::__is_insertable<std::ostream&, Y&>::value, "");
  static_assert(std::__is_insertable<std::ostream&&, Y&&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&, Z&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&&, Z&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&, Z&&>::value, "");
  static_assert(!std::__is_insertable<std::ostream&&, Z&&>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<X&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<X&&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<Y&>())),
		std::true_type>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<Y&&>())),
		std::true_type>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<Z&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(f(std::declval<Z&&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<X&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<X&&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<Y&>())),
		std::true_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<Y&&>())),
		std::true_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<Z&>())),
		std::false_type>::value, "");
  static_assert(std::is_same<decltype(g(std::declval<Z&&>())),
		std::false_type>::value, "");
}

int main()
{
  test01();
}
