/* { dg-require-effective-target pch_supported_debug } */
/* { dg-options "-I. -Winvalid-pch -g" } */

#include "valid-1.h"/* { dg-warning "created with -gnone, but used with -g" } */
/* { dg-error "No such file" "no such file" { target *-*-* } 0 } */
/* { dg-error "they were invalid" "invalid files" { target *-*-* } 0 } */
/* { dg-message "terminated" "" { target *-*-* } 0 } */

int x;
