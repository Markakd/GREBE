#include "harness.h"

vector unsigned char a;

static void test()
{ 
  check(sizeof(a) == 16, "sizeof(a)");
  check(((long)&a & 15) == 0, "alignof(a)");
  check((long)&a != 0, "&a");
  check(vec_all_eq(a,((vector unsigned char){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})), "value(a)");
}
