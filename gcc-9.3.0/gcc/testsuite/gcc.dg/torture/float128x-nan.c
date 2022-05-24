/* Test _Float128x NaNs.  */
/* { dg-do run } */
/* { dg-options "-fsignaling-nans" } */
/* { dg-add-options float128x } */
/* { dg-add-options ieee } */
/* { dg-require-effective-target float128x_runtime } */
/* { dg-require-effective-target fenv_exceptions } */

#define WIDTH 128
#define EXT 1
#include "floatn-nan.h"
