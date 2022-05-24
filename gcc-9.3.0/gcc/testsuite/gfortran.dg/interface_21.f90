! { dg-do compile }
! PR33162 INTRINSIC functions as ACTUAL argument
! Test case adapted from PR by Jerry DeLisle <jvdelisle@gcc.gnu.org>
module m
implicit none
contains
  subroutine sub(a)
    interface
      function a(x)
        real :: a, x
        intent(in) :: x
      end function a
    end interface
    print *, a(4.0)
  end subroutine sub
end module m

use m
implicit none
EXTERNAL foo  ! implicit interface is undefined
call sub(foo) ! { dg-error "is not a function" }
end
