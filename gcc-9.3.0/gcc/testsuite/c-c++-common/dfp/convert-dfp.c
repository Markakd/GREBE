/* { dg-options "-O0" } */

/* N1150 5.2 Conversions among decimal floating types and between
   decimal floating types and generic floating types.
   C99 6.3.1.5(3) New.

   Test various conversions involving decimal floating types. */

#ifndef	__STDC_WANT_DEC_FP__
#define __STDC_WANT_DEC_FP__ 1
#endif

#include "dfp-dbg.h"
#include <float.h>

volatile _Decimal32 d32;
volatile _Decimal64 d64;
volatile _Decimal128 d128;

int
main ()
{
  /* Conversions to larger types.  */
  d32 = 123.4df;
  d64 = d32;
  if (d64 != 123.4dd)
    FAILURE
  d128 = d32;
  if (d128 != 123.4dl)
    FAILURE
  d64 = 345.678dd;
  d128 = d64;
  if (d128 != 345.678dl)
    FAILURE

  /* Conversions to smaller types for which the value fits.  */
  d64 = 3456.789dd;
  d32 = d64;
  if (d32 != 3456.789df)
    FAILURE
  d128 = 123.4567dl;
  d32 = d128;
  if (d32 != 123.4567df)
    FAILURE

  d128 = 1234567890.123456dl;
  d64 = d128;
  if (d64 != 1234567890.123456dd)
    FAILURE

  /* Test demotion to non-representable decimal floating type. */

  /* Assumes a default rounding mode of 'near'.  This uses the rules
     describe in the 27 July 2005 draft of IEEE 754r, which are much
     more clear that what's described in draft 5 of N1107.  */

  /* Rounds to what _Decimal32 can handle.  */
  d64 = 9.99999949E96DD;
  d32 = d64;
  if (d32 != DEC32_MAX)
    FAILURE

  /* Rounds to more than _Decimal32 can handle.  */
  d64 = 9.9999995E96DD;
  d32 = d64;
  if (d32 != __builtin_infd32())
    FAILURE

  /* Rounds to what _Decimal32 can handle.  */
  d128 = 9.99999949E96DD;
  d32 = d128;
  if (d32 != DEC32_MAX)
    FAILURE

  /* Rounds to more than _Decimal32 can handle.  */
  d128= 9.9999995E96DD;
  d32 = d128;
  if (d32 != __builtin_infd32())
    FAILURE

  /* Rounds to what _Decimal64 can handle.  */
  d128 = 9.99999999999999949E384DL;
  d64 = d128;
  if (d64 != DEC64_MAX)
    FAILURE

  /* Rounds to more than _Decimal64 can handle.  */
  d128 = 9.9999999999999995E384DL;
  d64 = d128;
  if (d64 != __builtin_infd64())
    FAILURE

  FINISH
}
