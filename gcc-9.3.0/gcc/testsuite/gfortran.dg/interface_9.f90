! { dg-do compile }
! Test of the patch for PR30096, in which gfortran incorrectly.
! compared local with host associated interfaces.
! 
! Based on contribution by Harald Anlauf <anlauf@gmx.de>
!
module module1
  interface inverse
     module procedure A, B
  end interface
contains
  function A (X) result (Y)
    real                        :: X, Y
    Y = 1.0
  end function A
  function B (X) result (Y)
    integer                     :: X, Y
    Y = 3
  end function B
end module module1

module module2
  interface inverse
     module procedure C
  end interface
contains
  function C (X) result (Y)
    real                        :: X, Y
    Y = 2.0
  end function C
end module module2

program gfcbug48
  use module1, only : inverse
  call sub ()
  if (inverse(1.0_4) /= 1.0_4) STOP 1
  if (inverse(1_4) /= 3_4) STOP 2
contains
  subroutine sub ()
    use module2, only : inverse
    if (inverse(1.0_4) /= 2.0_4) STOP 3
    if (inverse(1_4) /= 3_4) STOP 4
  end subroutine sub
end program gfcbug48
