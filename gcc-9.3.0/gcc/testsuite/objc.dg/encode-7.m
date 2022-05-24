/* { dg-do run } */
/* { dg-skip-if "" { *-*-* } { "-fnext-runtime" } { "" } } */

#include <objc/runtime.h>
#include <stdlib.h>

struct f
{
  _Bool a;
};


int main(void)
{
  if (objc_sizeof_type (@encode (struct f)) != sizeof(struct f))
   abort ();
  return 0;
}
