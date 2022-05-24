! { dg-do run }
!
! PR39630: Fortran 2003: Procedure pointer components.
!
! Basic test for PPCs with FUNCTION interface and NOPASS.
!
! Contributed by Janus Weil <janus@gcc.gnu.org>

  type t
    procedure(fcn), pointer, nopass :: ppc
    procedure(abstr), pointer, nopass :: ppc1
    integer :: i
  end type

  abstract interface
    integer function abstr(x)
      integer, intent(in) :: x
    end function
  end interface

  type(t) :: obj
  procedure(fcn), pointer :: f
  integer :: base

  intrinsic :: iabs

! Check with interface from contained function
  obj%ppc => fcn
  base=obj%ppc(2)
  if (base/=4) STOP 1
  call foo (obj%ppc,3)

! Check with abstract interface
  obj%ppc1 => obj%ppc
  base=obj%ppc1(4)
  if (base/=8) STOP 1
  call foo (obj%ppc1,5)

! Check compatibility components with non-components  
  f => obj%ppc
  base=f(6)
  if (base/=12) STOP 1
  call foo (f,7)

contains

  integer function fcn(x)
    integer, intent(in) :: x
    fcn = 2 * x
  end function

  subroutine foo (arg, i)
    procedure (fcn), pointer :: arg
    integer :: i
    if (arg(i)/=2*i) STOP 1
  end subroutine

end
