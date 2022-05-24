/* Contributed by Nicola Pero - Tue Mar  6 23:05:53 CET 2001 */

#include <objc/objc.h>

/* Tests creating a root class and a subclass with an ivar and
   accessor methods; accessor methods implemented in a separate
   category */

@interface RootClass
{
  Class isa;
}
@end

@implementation RootClass
+ initialize { return self; }
@end

@interface SubClass : RootClass
{
  int state;
}
@end

@implementation SubClass
@end

@interface SubClass (Additions)
- (void) setState: (int)number;
- (int) state;
@end

@implementation SubClass (Additions)
- (void) setState: (int)number
{
  state = number;
}
- (int) state
{
  return state;
}
@end

#include "class-tests-1.h"
#define TYPE_OF_OBJECT_WITH_ACCESSOR_METHOD SubClass *
#include "class-tests-2.h"

int main (void)
{
  SubClass *object;

  test_class_with_superclass ("SubClass", "RootClass");

  /* The NeXT runtime's category implementation is lazy: categories are not attached 
     to classes until the class is initialized (at +initialize time).  */
#ifdef __NEXT_RUNTIME__
  [SubClass initialize];
#endif

  test_that_class_has_instance_method ("SubClass", @selector (setState:));
  test_that_class_has_instance_method ("SubClass", @selector (state));

  object = class_createInstance (objc_getClass ("SubClass"), 0);
  test_accessor_method (object, 0, 1, 1, -3, -3);

  return 0;
}
