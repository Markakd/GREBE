/* { dg-do compile { target { powerpc64*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */

/* Verify P9 vector bit-permute doubleword instruction.  */

#include <altivec.h>

vector unsigned long long
test_vbpermd (vector unsigned long long a, vector unsigned char b)
{
  return vec_bperm (a, b);
}

/* { dg-final { scan-assembler "vbpermd" } } */
