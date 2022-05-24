/* Test AAPCS layout (VFP variant for Neon types) */

/* { dg-do run { target arm_eabi } } */
/* { dg-require-effective-target arm_hard_vfp_ok } */
/* { dg-require-effective-target arm_neon_ok } */
/* { dg-require-effective-target arm_neon_hw } */
/* { dg-require-effective-target arm32 } */
/* { dg-add-options arm_neon } */


#ifndef IN_FRAMEWORK
#define VFP
#define NEON
#define TESTFILE "neon-vect5.c"
#include "neon-constants.h"


#include "abitest.h"
#else

ARG(int32x4_t, i32x4_constvec2, Q0) /* D0, D1 */
ARG(float, 3.0f, S4) /* D2, Q1 */
ARG(float32x4x2_t, f32x4x2_constvec1, Q2) /* Q2, Q3 - D4-D6 , s5-s12 */
ARG(double, 12.0, D3) /* Backfill this particular argument.  */
ARG(int32x4x2_t, i32x4x2_constvec2, STACK) 
ARG(float, 5.0f, STACK+sizeof(int32x4x2_t)) /* No backfill allowed.  */
LAST_ARG(int, 3, R0)

#endif
