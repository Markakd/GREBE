/* Use conditional compare */                                                                                         
/* { dg-options "-O2" } */
/* { dg-skip-if "" { arm_thumb1_ok } } */
/* { dg-final { scan-assembler "cmpeq" } } */

int f(int i, int j) 
{
  if ( (i == '+') && (j == '-') ) {
    return 1;
  } else {
    return 0;
  }
}
