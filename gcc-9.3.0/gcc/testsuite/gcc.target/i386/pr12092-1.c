/* PR rtl-optimization/12092  */
/* Test case reduced by Andrew Pinski <pinskia@physics.uc.edu> */
/* { dg-do compile } */
/* { dg-require-effective-target ia32 } */
/* { dg-options "-O2 -mtune=i486 -march=pentium4 -fprefetch-loop-arrays" } */

void DecodeAC(int index,int *matrix)
{
  int *mptr;

  for(mptr=matrix+index;mptr<matrix+64;mptr++) {*mptr = 0;}
}

