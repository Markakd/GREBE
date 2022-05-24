/* { dg-do compile } */
/* { dg-require-effective-target tls } */
/* { dg-require-effective-target global_constructor } */
/* { dg-options "-O2" } */

/* With emulated TLS, the constructor generated during IPA
   was not properly lowered to SSA form.  */

__thread int i __attribute__((common));
