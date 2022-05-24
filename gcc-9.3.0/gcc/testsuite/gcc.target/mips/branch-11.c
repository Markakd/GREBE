/* { dg-options "-mshared -mabi=n32" } */
/* { dg-final { scan-assembler "\tsd\t\\\$28," } } */
/* { dg-final { scan-assembler "\tld\t\\\$28," } } */
/* { dg-final { scan-assembler "\taddiu\t\\\$28,\\\$28,%lo\\(%neg\\(%gp_rel\\(foo\\)\\)\\)\n" } } */
/* { dg-final { scan-assembler "\tlw\t\\\$1,%got_page\\(\[^)\]*\\)\\(\\\$28\\)\n" } } */
/* { dg-final { scan-assembler "\taddiu\t\\\$1,\\\$1,%got_ofst\\(\[^)\]*\\)\n" } } */
/* { dg-final { scan-assembler "\tjrc?\t\\\$1\n" } } */

#include "branch-helper.h"

NOCOMPRESSION void
foo (int (*bar) (void), int *x)
{
  *x = bar ();
  if (__builtin_expect (*x == 0, 1))
    OCCUPY_0x1fffc;
}
