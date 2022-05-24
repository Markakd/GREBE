// Copyright (C) 2016-2019 Free Software Foundation, Inc.
//
// This file is part of the GNU ISO C++ Library.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the
// Free Software Foundation; either version 3, or (at your option)
// any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this library; see the file COPYING3.  If not see
// <http://www.gnu.org/licenses/>.
//
// { dg-do run { target c++11 } }

#include <unordered_set>

#include <testsuite_hooks.h>

template<typename _USet>
  void test(int threshold)
  {
    _USet us;
    auto nb_reserved = us.bucket_count();
    us.reserve(nb_reserved);
    auto bkts = us.bucket_count();
    for (int i = 0; i != threshold; ++i)
      {
	if (i >= nb_reserved)
	  {
	    nb_reserved = bkts;
	    us.reserve(nb_reserved);
	    bkts = us.bucket_count();
	  }

	us.insert(i);

	VERIFY( us.bucket_count() == bkts );
      }
  }

template<typename _Value>
  using unordered_set_power2_rehash =
  std::_Hashtable<_Value, _Value, std::allocator<_Value>,
		  std::__detail::_Identity,
		  std::equal_to<_Value>,
		  std::hash<_Value>,
		  std::__detail::_Mask_range_hashing,
		  std::__detail::_Default_ranged_hash,
		  std::__detail::_Power2_rehash_policy,
		  std::__detail::_Hashtable_traits<false, true, true>>;

int main()
{
  test<std::unordered_set<int>>(150);
  test<unordered_set_power2_rehash<int>>(150);
  return 0;
}
