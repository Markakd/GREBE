#include <objc/objc.h>

struct A {
  int i;
  float f;
  int a:3;
  int b:2;
};

@interface MyObject
{
  Class isa;
  int i;
  float f[3];
  struct A a;
}
@end

@implementation MyObject
@end

#include "bf-common.h"
