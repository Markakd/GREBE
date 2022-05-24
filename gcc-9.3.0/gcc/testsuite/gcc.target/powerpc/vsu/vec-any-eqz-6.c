/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9" } */

#include <altivec.h>

int
test_any_equal_or_zero (vector unsigned int *arg1_p,
			vector unsigned int *arg2_p)
{
  vector unsigned int arg_1 = *arg1_p;
  vector unsigned int arg_2 = *arg2_p;

  return vec_any_eqz (arg_1, arg_2);
}

/* { dg-final { scan-assembler "vcmpnezw." } } */
