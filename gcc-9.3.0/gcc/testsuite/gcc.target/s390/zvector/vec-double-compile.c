/* { dg-do compile } */
/* { dg-options "-O3 -mzarch -march=arch13 -mzvector -fno-asynchronous-unwind-tables -dp" } */

#include <vecintrin.h>

vector double
vcdgb (vector signed long long a)
{
  return vec_double (a);
}

/* { dg-final { scan-assembler-times "vcdgb.*\n\tvcdgb.*floatv2div2df2" 1 } } */

vector double
vcdlgb (vector unsigned long long a)
{
  return vec_double (a);
}

/* { dg-final { scan-assembler-times "vcdlgb.*\n\tvcdlgb.*floatunsv2div2df2" 1 } } */

vector double
vcdgb_mem (vector signed long long *a)
{
  return vec_double (*a);
}

vector double
vcdlgb_mem (vector unsigned long long *a)
{
  return vec_double (*a);
}

vector double
vcdgb_imm ()
{
  return vec_double ((vector signed long long) { 1, -2 });
}

vector double
vcdlgb_imm ()
{
  return vec_double ((vector unsigned long long){ 1, 2 });
}

/* { dg-final { scan-assembler-times "vcdgb\t" 3 } } */
/* { dg-final { scan-assembler-times "vcdlgb\t" 3 } } */
