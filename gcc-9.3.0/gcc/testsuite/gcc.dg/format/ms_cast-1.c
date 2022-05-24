/* Test for strings cast through integer types: should not be treated
   as format strings unless the types are of the same width as
   pointers (intptr_t or similar).  */
/* Origin: Joseph Myers <joseph@codesourcery.com> */
/* { dg-do compile { target { *-*-mingw* } } } */
/* { dg-options "-Wformat" } */

#define USE_SYSTEM_FORMATS
#include "format.h"

void
f (int x)
{
  printf("%s", x); /* { dg-warning "format" } */
  printf((char *)(size_t)"%s", x); /* { dg-warning "format" } */
  printf((char *)(char)"%s", x); /* { dg-warning "cast from pointer to integer of different size" } */
}
