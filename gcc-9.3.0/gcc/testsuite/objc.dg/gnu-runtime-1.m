/* Test that compiling for the GNU runtime works (regardless of
   the system runtime used).  */
/* Author: Ziemowit Laski <zlaski@apple.com>  */
/* { dg-do compile } */
/* { dg-skip-if "" { *-*-* } { "-fnext-runtime" } { "" } } */

#include "../objc-obj-c++-shared/TestsuiteObject.h"

@interface FooBar: TestsuiteObject
- (void)boo;
@end

int main ()
{
  id fooBarInst = [[FooBar alloc] init];
  [fooBarInst boo];
  return 0;
}

