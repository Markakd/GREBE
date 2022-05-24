/* Contributed by Nicola Pero - Fri Mar  9 21:35:47 CET 2001 */

#include <stdlib.h>
#include "../../objc-obj-c++-shared/TestsuiteObject.m"

/* Test defining a protocol, a class adopting it, and using an object
   of type `id <protocol>'. */

@protocol Enabling
- (BOOL) isEnabled;
- (void) setEnabled: (BOOL)flag;
@end

@interface Feature : TestsuiteObject <Enabling>
{
  const char *name;
  BOOL isEnabled;
}
@end

@implementation Feature
- (BOOL) isEnabled
{
  return isEnabled;
}
- (void) setEnabled: (BOOL)flag
{
  isEnabled = flag;
}
@end

int main (void)
{
  id <Enabling> object;

  object = [Feature new];

  [object setEnabled: YES];
  if (![object isEnabled])
    {
      abort ();
    }

  return 0;
}

