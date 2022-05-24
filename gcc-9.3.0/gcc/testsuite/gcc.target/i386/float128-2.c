/* PR target/36710 */

/* { dg-do run } */
/* { dg-options "-Os -msse2" } */
/* { dg-require-effective-target sse2 } */

#include "sse2-check.h"

extern void abort (void);

static void
sse2_test (void)
{
  static volatile __float128 a = 123.0q;

  if ((int) a != 123)
    abort ();
}
