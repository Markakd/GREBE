/* { dg-do compile { target { *-*-linux* && lp64 } } } */
/* { dg-options "-mabi=ms -fdump-rtl-dfinit" } */

void
__attribute__((sysv_abi))
foo () {};

/* { dg-final { scan-rtl-dump "entry block defs\[^\\n]*\\\[si\\]\[^\\n]*\\\[di\\]" "dfinit" } } */
