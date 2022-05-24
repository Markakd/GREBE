/* { dg-do compile { target { powerpc64le-*-* } } } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */
/* { dg-require-effective-target powerpc_p9vector_ok } */

#include <altivec.h>

vector float
foo_r (float a)
{
  return (vector float) { a, a, a, a };			/* xscvdpspn/xxspltw */
}

vector float
foo_r2 (float a)
{
  return vec_splats (a);				/* xscvdpspn/xxspltw */
}

vector float
foo_g (float *a)
{
  float f = *a;

  __asm__ (" # %0" : "+r" (f));
  return (vector float) { f, f, f, f };			/* mtvsrws */
}

vector float
foo_p (float *a)
{
  return (vector float) { *a, *a, *a, *a };		/* lxvwsx */
}

/* { dg-final { scan-assembler-times "xscvdpspn" 2 } } */
/* { dg-final { scan-assembler-times "xxspltw"   2 } } */
/* { dg-final { scan-assembler-times "mtvsrws"   1 } } */
/* { dg-final { scan-assembler-times "lxvwsx"    1 } } */
