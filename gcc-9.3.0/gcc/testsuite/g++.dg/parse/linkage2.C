// PR c++/27884

extern "C" void foo(register int *my_perl);	// { dg-error "ISO C\\+\\+17 does not allow 'register' storage class specifier" "" { target c++17 } }
