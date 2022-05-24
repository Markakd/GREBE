/* Test if the Objective-C @encode machinery distinguishes between
   'BOOL *' (which should be encoded as '^c') and 'char *' (which
   should be encoded as '*').  */
/* Contributed by Ziemowit Laski <zlaski@apple.com>.  */
/* { dg-do run { target *-*-darwin* } } */
/* { dg-skip-if "" { *-*-* } { "-fgnu-runtime" } { "" } } */

#include <string.h>           
#include <stdlib.h>
#include <objc/objc.h>

int main(void) {
  const char *BOOL_ptr = @encode(BOOL *);
  const char *char_ptr = @encode(char *);
  
  if(strcmp(BOOL_ptr, "^c"))
    abort();

  if(strcmp(char_ptr, "*"))
    abort();

  return 0;
}
