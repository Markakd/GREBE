/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-require-effective-target powerpc_p9vector_ok } */
/* { dg-options "-mdejagnu-cpu=power9 -O1" } */

volatile int a;
int b;
void fn1(void) { b + (long)b || a; }
