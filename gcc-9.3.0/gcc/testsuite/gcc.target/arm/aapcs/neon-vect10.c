/* Test AAPCS layout (VFP variant for Neon types) */

/* { dg-do run { target arm_eabi } } */
/* { dg-require-effective-target arm_hard_vfp_ok }  */
/* { dg-require-effective-target arm_neon_fp16_hw } */
/* { dg-add-options arm_neon_fp16 } */

#ifndef IN_FRAMEWORK
#define VFP
#define NEON
#define TESTFILE "neon-vect10.c"
#include "neon-constants.h"

#include "abitest.h"
#else

ARG (int32x4_t, i32x4_constvec2, Q0) /* D0, D1.  */
#if defined (__ARM_BIG_ENDIAN)
ARG (__fp16, 3.0f, S4 + 2) /* D2, Q1.  */
#else
ARG (__fp16, 3.0f, S4) /* D2, Q1.  */
#endif
ARG (int32x4x2_t, i32x4x2_constvec1, Q2) /* Q2, Q3 - D4-D6 , s5-s12.  */
ARG (double, 12.0, D3) /* Backfill this particular argument.  */
#if defined (__ARM_BIG_ENDIAN)
ARG (__fp16, 5.0f, S5 + 2) /* Backfill in S5.  */
#else
ARG (__fp16, 5.0f, S5) /* Backfill in S5.  */
#endif
ARG (int32x4x2_t, i32x4x2_constvec2, STACK)
LAST_ARG (int, 3, R0)
#endif
