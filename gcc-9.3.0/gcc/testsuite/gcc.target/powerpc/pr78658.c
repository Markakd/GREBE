/* { dg-do compile { target { powerpc64*-*-* && lp64 } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9 -O2" } */

/* This caused an unrecognizable insn message on development versions of GCC 7.  */

float a;
char b;

void c(void)
{
  a = b = a;
}
