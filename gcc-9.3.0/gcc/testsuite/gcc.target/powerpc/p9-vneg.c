/* { dg-do compile { target { powerpc64*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */

/* Verify P9 vector negate instructions.  */

vector long long v2di_neg (vector long long a) { return -a; }
vector int v4si_neg (vector int a) { return -a; }

/* { dg-final { scan-assembler "vnegd" } } */
/* { dg-final { scan-assembler "vnegw" } } */
