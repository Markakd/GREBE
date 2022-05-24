/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9" } */

#include <altivec.h>

vector bool char
fetch_data (vector unsigned char *arg1_p, vector unsigned char *arg2_p)
{
  vector unsigned char arg_1 = *arg1_p;
  vector unsigned char arg_2 = *arg2_p;

  return vec_cmpnez (arg_1, arg_2);
}

/* { dg-final { scan-assembler "vcmpnezb" } } */
