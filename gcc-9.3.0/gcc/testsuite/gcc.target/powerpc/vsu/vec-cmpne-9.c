/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9" } */

#include <altivec.h>

vector bool long long
fetch_data (vector double *arg1_p, vector double *arg2_p)
{
  vector double arg_1 = *arg1_p;
  vector double arg_2 = *arg2_p;

  return vec_cmpne (arg_1, arg_2);
}

/* { dg-final { scan-assembler "xvcmpeqdp" } } */
