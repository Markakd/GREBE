/* Contributed by Nicola Pero <nicola.pero@meta-innovation.com>, November 2010.  */
/* { dg-do compile } */

/* Test that protocol qualifiers are maintained correctly when a
   @class is replaced by its @interface.  */

#include <objc/objc.h>

@protocol MyProtocol
- (void) method;
@end

@class MyClass;

static MyClass <MyProtocol> *object1;
static MyClass *object2;

/* Declarating the @interface now will need to update all the existing
   ObjC types referring to MyClass with the new information.  We need
   to test that protocol information is not lost in the process.  */
@interface MyClass
@end

void test1 (void)
{
  [object1 method]; /* Ok */
  [object2 method]; /* { dg-warning ".MyClass. may not respond to ..method." } */
                    /* { dg-warning "without a matching method" "" { target *-*-* } .-1 } */
                    /* { dg-warning "will be assumed to return" "" { target *-*-* } .-2 } */
                    /* { dg-warning "as arguments" "" { target *-*-* } .-3 } */
}
