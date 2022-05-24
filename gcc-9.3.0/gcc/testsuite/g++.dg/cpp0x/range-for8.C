// Test for range-based for loop when the declarator declares
// a new type

// { dg-do compile { target c++11 } }

#include <initializer_list>

void test()
{
    for (struct S { } *x : { (S*)0, (S*)0 } ) // { dg-error "types may not be defined" }
        ;

    for (struct S { } x : { S(), S() } ) // { dg-error "types may not be defined" }
        ;
}
