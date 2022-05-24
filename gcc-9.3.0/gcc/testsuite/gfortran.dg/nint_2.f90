! Test that NINT gives right results even in corner cases
!
! PR 31202
! http://gcc.gnu.org/ml/fortran/2005-04/msg00139.html
!
! { dg-do run }
! { dg-xfail-run-if "PR 33271, math library bug" { powerpc-ibm-aix* *-*-mingw* } { "-O0" } { "" } }
  real(kind=8) :: a
  integer(kind=8) :: i1, i2
  real :: b
  integer :: j1, j2

  a = nearest(0.5_8,-1.0_8)
  i2 = nint(nearest(0.5_8,-1.0_8))
  i1 = nint(a)
  if (i1 /= 0 .or. i2 /= 0) STOP 1

  a = 0.5_8
  i2 = nint(0.5_8)
  i1 = nint(a)
  if (i1 /= 1 .or. i2 /= 1) STOP 2

  a = nearest(0.5_8,1.0_8)
  i2 = nint(nearest(0.5_8,1.0_8))
  i1 = nint(a)
  if (i1 /= 1 .or. i2 /= 1) STOP 3

  b = nearest(0.5,-1.0)
  j2 = nint(nearest(0.5,-1.0))
  j1 = nint(b)
  if (j1 /= 0 .or. j2 /= 0) STOP 4

  b = 0.5
  j2 = nint(0.5)
  j1 = nint(b)
  if (j1 /= 1 .or. j2 /= 1) STOP 5

  b = nearest(0.5,1.0)
  j2 = nint(nearest(0.5,1.0))
  j1 = nint(b)
  if (j1 /= 1 .or. j2 /= 1) STOP 6

  a = 4503599627370497.0_8
  i1 = nint(a,kind=8)
  i2 = nint(4503599627370497.0_8,kind=8)
  if (i1 /= i2 .or. i1 /= 4503599627370497_8) STOP 7

  a = -4503599627370497.0_8
  i1 = nint(a,kind=8)
  i2 = nint(-4503599627370497.0_8,kind=8)
  if (i1 /= i2 .or. i1 /= -4503599627370497_8) STOP 8
  end
