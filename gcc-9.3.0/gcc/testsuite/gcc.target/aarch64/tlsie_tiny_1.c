/* { dg-do compile } */
/* { dg-require-effective-target tls_native } */
/* { dg-options "-O2 -fpic -ftls-model=initial-exec -mcmodel=tiny" } */

#include "tls_1.x"

/* { dg-final { scan-assembler-times ":gottprel:" 2 } } */
