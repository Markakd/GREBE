/* { dg-do compile { target { powerpc*-*-linux* && lp64 } } } */
/* { dg-skip-if "" { powerpc*-*-darwin* } } */
/* { dg-skip-if "" { powerpc*-*-*spe* } } */
/* { dg-require-effective-target powerpc_p8vector_ok } */
/* { dg-options "-mpower8-vector -O2" } */

/* Test that we generate XSCVDPSP instead of FRSP and XSCVDPSPN when we combine
   a round from double to float and moving the float value to a GPR.  */

union u {
  float f;
  unsigned int ui;
  int si;
};

unsigned int
ui_d (double d)
{
  union u x;
  x.f = d;
  return x.ui;
}

/* { dg-final { scan-assembler     {\mmfvsrwz\M}   } } */
/* { dg-final { scan-assembler     {\mxscvdpsp\M}  } } */
/* { dg-final { scan-assembler-not {\mmfvsrd\M}    } } */
/* { dg-final { scan-assembler-not {\mmtvsrwz\M}   } } */
/* { dg-final { scan-assembler-not {\mmtvsrd\M}    } } */
/* { dg-final { scan-assembler-not {\mxscvdpspn\M} } } */
/* { dg-final { scan-assembler-not {\msrdi\M}      } } */
