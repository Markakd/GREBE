/* C99 6.8.5.2: The for statement.  */

#include <stdio.h>
#include <stdlib.h>
#include "dfp-dbg.h"

void
f32 (void)
{
  _Decimal32 d;
  int i;

  for (d = 1.1df, i=0; d <= 1.5df; d += 0.1df)
    i++;

  if (i != 5)
    FAILURE
}

void
f64 (void)
{
  _Decimal64 d;
  int i;

  for (d = 1.1dd, i=0; d <= 1.5dd; d += 0.1dd)
    i++;

  if (i != 5)
    FAILURE
}

void
f128 (void)
{
  _Decimal128 d;
  int i;

  for (d = 1.1dl, i=0; d <= 1.5dl; d += 0.1dl)
    i++;

  if (i != 5)
    FAILURE
}

int
main ()
{
  int i;

  f32 ();
  f64 ();
  f128 ();
  
  FINISH
  return (0);
}
