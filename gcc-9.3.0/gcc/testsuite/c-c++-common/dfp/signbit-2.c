/* { dg-options "-O1" } */

/* Check that the compiler uses builtins for signbit; if not the link
   will fail because library functions are in libm.  */
/* See PR51867.
   Since GCC uses library call when optimizing for "-O0", this test
   case requires at least "-O1" level optimization now.  */

#include "dfp-dbg.h"

volatile _Decimal32 sd = 2.3df;
volatile _Decimal64 dd = -4.5dd;
volatile _Decimal128 tf = 5.3dl;
volatile float f = 1.2f;
volatile double d = -7.8;
volatile long double ld = 3.4L;

EXTERN int signbitf (float);
EXTERN int signbit (double);
EXTERN int signbitl (long double);
EXTERN int signbitd32 (_Decimal32);
EXTERN int signbitd64 (_Decimal64);
EXTERN int signbitd128 (_Decimal128);

int
main ()
{
  if (signbitf (f) != 0) FAILURE
  if (signbit (d) == 0) FAILURE
  if (signbitl (ld) != 0) FAILURE
  if (signbitd32 (sd) != 0) FAILURE
  if (signbitd64 (dd) == 0) FAILURE
  if (signbitd128 (tf) != 0) FAILURE

  FINISH
}
