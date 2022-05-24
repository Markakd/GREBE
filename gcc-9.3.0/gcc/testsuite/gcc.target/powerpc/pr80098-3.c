/* { dg-do compile { target { powerpc64*-*-* } } } */
/* { dg-require-effective-target powerpc_vsx_ok } */
/* { dg-options "-mdejagnu-cpu=power7 -mno-vsx -mcrypto" } */

int i;

/* { dg-error "'-mno-vsx' turns off '-mcrypto'"      "PR80098" { target *-*-* } 0 } */
