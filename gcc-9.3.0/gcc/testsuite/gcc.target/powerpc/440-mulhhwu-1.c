/* Test generation of mulhhwu on 440.  */
/* Origin: Joseph Myers <joseph@codesourcery.com> */
/* { dg-do compile } */
/* { dg-require-effective-target ilp32 } */
/* { dg-options "-O2 -mdejagnu-cpu=440" } */

/* { dg-final { scan-assembler "mulhhwu " } } */

unsigned int
f(unsigned int b, unsigned int c)
{
  unsigned int a = (b >> 16) * (c >> 16);
  return a;
}
