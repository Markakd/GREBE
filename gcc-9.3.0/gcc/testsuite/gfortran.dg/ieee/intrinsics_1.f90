! { dg-do run }
! { dg-additional-options "-fno-range-check" }
!
! Check compile-time simplification of functions FRACTION, EXPONENT,
! SPACING, RRSPACING and SET_EXPONENT for special values.

program test
  implicit none
  real, parameter :: inf = 2 * huge(0.)
  real, parameter :: nan = 0. / 0.

  call check_positive_zero(fraction(0.))
  call check_negative_zero(fraction(-0.))
  if (.not. isnan(fraction(inf))) STOP 1
  if (.not. isnan(fraction(-inf))) STOP 2
  if (.not. isnan(fraction(nan))) STOP 3

  if (exponent(0.) /= 0) STOP 4
  if (exponent(-0.) /= 0) STOP 5
  if (exponent(inf) /= huge(0)) STOP 6
  if (exponent(-inf) /= huge(0)) STOP 7
  if (exponent(nan) /= huge(0)) STOP 8

  if (spacing(0.) /= spacing(tiny(0.))) STOP 9
  if (spacing(-0.) /= spacing(tiny(0.))) STOP 10
  if (.not. isnan(spacing(inf))) STOP 11
  if (.not. isnan(spacing(-inf))) STOP 12
  if (.not. isnan(spacing(nan))) STOP 13

  call check_positive_zero(rrspacing(0.))
  call check_positive_zero(rrspacing(-0.))
  if (.not. isnan(rrspacing(inf))) STOP 14
  if (.not. isnan(rrspacing(-inf))) STOP 15
  if (.not. isnan(rrspacing(nan))) STOP 16

  call check_positive_zero(set_exponent(0.,42))
  call check_negative_zero(set_exponent(-0.,42))
  if (.not. isnan(set_exponent(inf, 42))) STOP 17
  if (.not. isnan(set_exponent(-inf, 42))) STOP 18
  if (.not. isnan(set_exponent(nan, 42))) STOP 19

contains

  subroutine check_positive_zero(x)
    use ieee_arithmetic
    implicit none
    real, value :: x

    if (ieee_class (x) /= ieee_positive_zero) STOP 20
  end

  subroutine check_negative_zero(x)
    use ieee_arithmetic
    implicit none
    real, value :: x

    if (ieee_class (x) /= ieee_negative_zero) STOP 21
  end

end
