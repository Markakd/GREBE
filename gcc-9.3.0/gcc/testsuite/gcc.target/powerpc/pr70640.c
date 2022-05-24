/* { dg-do compile { target { powerpc*-*-linux* } } } */
/* { dg-require-effective-target powerpc_float128_sw_ok } */
/* { dg-options "-O2 -mdejagnu-cpu=power8 -mfloat128" } */

__float128 foo (__float128 a) { return -a; }

/* { dg-final { scan-assembler "xxlorc\|vspltisw" } } */
/* { dg-final { scan-assembler "xxlxor" } } */
/* { dg-final { scan-assembler "vslb"   } } */
/* { dg-final { scan-assembler "vsldoi" } } */
