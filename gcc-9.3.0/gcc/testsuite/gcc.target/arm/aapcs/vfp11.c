/* Test AAPCS layout (VFP variant) */

/* { dg-do run { target arm_eabi } } */
/* { dg-require-effective-target arm_hard_vfp_ok } */
/* { dg-require-effective-target arm32 } */
/* { dg-options "-O -mfpu=vfp -mfloat-abi=hard" } */

#ifndef IN_FRAMEWORK
#define VFP
#define TESTFILE "vfp11.c"

__complex__ x = 1.0+2.0i;

struct y
{
  int p;
  int q;
  int r;
  int s;
} v = { 1, 2, 3, 4 };

struct z
{
  double x[4];
};

struct z a = { 5.0, 6.0, 7.0, 8.0 };
struct z b = { 9.0, 10.0, 11.0, 12.0 };

#define MYFUNCTYPE struct y

#include "abitest.h"
#else
  ARG(int, 7, R1)
  ARG(struct y, v, R2)
  ARG(struct z, a, D0)
  ARG(struct z, b, D4)
  LAST_ARG(double, 0.5, STACK+8)
#endif
