/* Test for warnings for missing format attributes.  Don't warn if no
   relevant parameters for a format attribute; see c/1017.  */
/* Origin: Joseph Myers <jsm28@cam.ac.uk> */
/* { dg-do compile { target { *-*-mingw* } } } */
/* { dg-options "-std=gnu99 -Wmissing-format-attribute" } */

#define USE_SYSTEM_FORMATS
#include "format.h"

void
foo (int i, ...)
{
  va_list ap;
  va_start (ap, i);
  vprintf ("Foo %s bar %s", ap); /* { dg-bogus "candidate" "bogus printf attribute warning" } */
  va_end (ap);
}
