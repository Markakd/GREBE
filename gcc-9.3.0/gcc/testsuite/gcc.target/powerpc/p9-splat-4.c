/* { dg-do compile { target { powerpc64*-*-* && lp64 } } } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */
/* { dg-require-effective-target powerpc_p9vector_ok } */

#include <altivec.h>

vector long long foo (long long a) { return (vector long long) { a, a }; }

/* { dg-final { scan-assembler "mtvsrdd" } } */
