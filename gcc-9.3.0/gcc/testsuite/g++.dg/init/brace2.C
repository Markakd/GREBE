// { dg-do compile }
// [dcl.init] paragraph 13.
int x = { 2 };
const char * y = { "hello" };
int a = 2;
int b = { 2,3 }; // { dg-error "5:scalar object 'b' requires one element in initializer" }
int c = { { 2 } } ; // { dg-error "braces around scalar initializer" }
int d = {}; // { dg-error "initializer" "" { target { ! c++11 } } }
int e = {{}}; // { dg-error "braces around scalar initializer" }
