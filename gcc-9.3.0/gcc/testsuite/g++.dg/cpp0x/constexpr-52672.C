// PR c++/52672
// { dg-do compile { target c++11 } }

__extension__ typedef __SIZE_TYPE__ * ul_ptr;
constexpr unsigned long a = *((ul_ptr)0x0); // { dg-error "" }
constexpr unsigned long b = *((ul_ptr)(*((ul_ptr)0x0))); // { dg-error "" }
constexpr unsigned long c = *((ul_ptr)*((ul_ptr)(*((ul_ptr)0x0)))); // { dg-error "" }
