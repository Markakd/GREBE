/* { dg-do compile { target { powerpc64*-*-* && lp64 } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */

vector long
merge (long a, long b)
{
  return (vector long) { a, b };
}

/* { dg-final { scan-assembler "mtvsrdd" } } */
