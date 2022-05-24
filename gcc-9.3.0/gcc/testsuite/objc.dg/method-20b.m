/* Check if array and function parameters get decayed to pointers as
   they should.  */
/* { dg-do run } */
/* { dg-options "-O2" } */
/* { dg-xfail-run-if "Needs OBJC2 ABI" { *-*-darwin* && { lp64 && { ! objc2 } } } { "-fnext-runtime" } { "" } } */

#include "../objc-obj-c++-shared/TestsuiteObject.m"
#include <string.h>
#include <stdlib.h>

static char global_buf[20];

char *strcpy_like_callee(const char *s) {
  strcpy(global_buf, s);
  return global_buf;
}  

typedef char io_string_t[512];
typedef char *(func_type)(const char *);

@interface DeviceObject: TestsuiteObject
- (void) func:(func_type)func stucPathInIORegistry:(io_string_t)ioRegPath;
@end
@implementation DeviceObject
- (void) func:(func_type)func stucPathInIORegistry:(io_string_t)ioRegPath
{
    func(ioRegPath);
}
@end

int main (void) {
  io_string_t my_string;
  DeviceObject *obj = [DeviceObject new];

  strcpy (my_string, "Hello!");
  strcpy (global_buf, "Good-bye!");

  [obj func:strcpy_like_callee stucPathInIORegistry:my_string];

  if (strcmp (global_buf, "Hello!"))
    abort ();

  return 0;
}
