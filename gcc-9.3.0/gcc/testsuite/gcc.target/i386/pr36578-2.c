/* Test for unsafe floating-point conversions.  */
/* { dg-do run } */
/* { dg-options "-msse2 -mfpmath=sse" } */
/* { dg-require-effective-target sse2 } */

#include "sse2-check.h"

extern void abort (void);
extern void exit (int);
extern int printf(const char *, ...);

volatile double d1 = 0x1.000001p0;
volatile double d2 = 0x1p-54;
volatile double d2d = 0x1p-52;
volatile float f = 0x1.000002p0f;
volatile float f2;

static void
sse2_test (void)
{
  if (sizeof(long double) > sizeof(double)  ) {
	f2 = (float)((long double)d1 + (long double)d2);
  } else {
	f2 = (float)((long double)d1 + (long double)d2d);
  }
  if (f != f2)
    abort ();
  exit (0);
}
