/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9" } */

#include <altivec.h>

int
test_all_not_equal (vector long long *arg1_p, vector long long *arg2_p)
{
  vector long long arg_1 = *arg1_p;
  vector long long arg_2 = *arg2_p;

  return vec_all_ne (arg_1, arg_2);
}

/* { dg-final { scan-assembler "vcmpequd." } } */
