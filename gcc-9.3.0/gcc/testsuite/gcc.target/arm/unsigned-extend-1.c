/* { dg-do compile } */
/* { dg-options "-O2" } */

unsigned char foo (unsigned char c)
{
  return (c >= '0') && (c <= '9');
}

/* { dg-final { scan-assembler-not "uxtb" } } */
