! { dg-do run }
! Transformational intrinsic DOT_PRODUCT as initialization expression.

  INTEGER, PARAMETER :: n = 10
  INTEGER, PARAMETER :: a(n) = 1
  INTEGER, PARAMETER :: p = DOT_PRODUCT(a, a)
  INTEGER, PARAMETER :: e = DOT_PRODUCT(SHAPE(1), SHAPE(1))

  IF (p /= n) STOP 1
  IF (e /= 0) STOP 2
END
