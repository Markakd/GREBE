// Ensure that generic lambdas properly construct and destroy user types.
// { dg-do compile { target c++14 } }
// { dg-options "-DUSE_EXPLICIT_TEMPLATE_SYNTAX" }

#include "lambda-generic-udt.C"
