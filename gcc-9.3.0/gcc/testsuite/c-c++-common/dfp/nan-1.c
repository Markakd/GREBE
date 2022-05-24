/* N1150 4: Characteristics of decimal floating types (not explicit)
   C99 5.2.4.2.2: Characteristics of floating types.
   A few simple checks on arithmetic operations. */

#include "dfp-dbg.h"

int main()
{
  /* Some possibly non-obvious tests, but most logical
     operations on NaN return false, including NaN == NaN. */
  if (__builtin_nand32("") == __builtin_nand32(""))
    FAILURE

  if (__builtin_nand64("") == __builtin_nand64(""))
    FAILURE

  if (__builtin_nand128("") == __builtin_nand128(""))
    FAILURE
  
  if (!(__builtin_nand32("") != __builtin_nand32("")))
    FAILURE

  if (!(__builtin_nand64("") != __builtin_nand64("")))
    FAILURE

  if (!(__builtin_nand128("") != __builtin_nand128("")))
    FAILURE

  if (__builtin_nand32("") > __builtin_nand32(""))
    FAILURE

  if (__builtin_nand64("") >= __builtin_nand64(""))
    FAILURE

  if (__builtin_nand128("") <  __builtin_nand128(""))
    FAILURE

  if (-__builtin_nand128("") <  +__builtin_nand128(""))
    FAILURE

  /* 0.0/0.0 => NaN, but NaN != NaN.  */
  if (0.0df/0.0dl == __builtin_nand32(""))
    FAILURE

  /* 0.0 * INF => NaN.  */
  if (!__builtin_isnand32 (0.0df * __builtin_infd32()))
    FAILURE

  if (!__builtin_isnand64 (0.0dd * __builtin_infd64()))
    FAILURE

  if (!__builtin_isnand128 (0.0dd * __builtin_infd128()))
    FAILURE

  /* INF - INF => NaN.  */
  if (!__builtin_isnand32 (__builtin_infd32() - __builtin_infd32()))
    FAILURE

  if (!__builtin_isnand64 (__builtin_infd64() - __builtin_infd64()))
    FAILURE

  if (!__builtin_isnand128 (__builtin_infd128() - __builtin_infd128()))
    FAILURE

  /* INF/INF => NaN.  */
  if (!__builtin_isnand32 (__builtin_infd32()/__builtin_infd32()) )
    FAILURE

  if (!__builtin_isnand64 (__builtin_infd64()/__builtin_infd64()) )
    FAILURE

  if (!__builtin_isnand128 (__builtin_infd128()/__builtin_infd128()) )
    FAILURE
  
  /* 0.0/0.0 => NaN, but NaN != NaN.  */
  if ((0.0dd/0.0df) == (0.0dd/0.0df))
    FAILURE

  if (__builtin_nand32("") <  __builtin_infd32())
    FAILURE

  if (__builtin_nand32("") >=  __builtin_infd32())
    FAILURE

  /* Fixme: Add sqrtdf(-x.df) test when sqrt is supported. */

  if (!__builtin_isnand32(__builtin_nand32("")))
    FAILURE

  if (!__builtin_isnand64(__builtin_nand64("")))
    FAILURE

  if (!__builtin_isnand128(__builtin_nand128("")))
    FAILURE

  if (!__builtin_isnand128(8.0df * __builtin_nand128("")))
    FAILURE

  if (!__builtin_isnand32(8.1dl - __builtin_nand32("")))
    FAILURE

  if (!__builtin_isnand128(__builtin_nand64("") + __builtin_nand128("")))
    FAILURE

  FINISH
}
