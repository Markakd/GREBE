/* Verify that overloaded built-ins for vec_eqv with int
   inputs produce the right results.  */

/* { dg-do compile } */
/* { dg-require-effective-target powerpc_p8vector_ok } */
/* { dg-options "-mpower8-vector -O2" } */

#include <altivec.h>

vector bool int
test1 (vector bool int x, vector bool int y)
{
  return vec_eqv (x, y);
}

vector signed int
test3 (vector signed int x, vector signed int y)
{
  return vec_eqv (x, y);
}

vector unsigned int
test6 (vector unsigned int x, vector unsigned int y)
{
  return vec_eqv (x, y);
}

/* { dg-final { scan-assembler-times "xxleqv" 3 } } */
