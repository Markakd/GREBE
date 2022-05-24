! { dg-do compile }
!
! PR 40869: [F03] PPC assignment checking
!
! Contributed by Janus Weil <janus@gcc.gnu.org>

implicit none

interface func
  procedure f1,f2
end interface

interface operator(.op.)
  procedure f1,f2
end interface

type :: t1
  procedure(integer), pointer, nopass :: ppc
end type

type :: t2
  procedure(real), pointer, nopass :: ppc
end type

type(t1) :: o1
type(t2) :: o2
procedure(logical),pointer :: pp1
procedure(complex),pointer :: pp2

pp1 => pp2        ! { dg-error "Type mismatch in function result" }
pp2 => o2%ppc     ! { dg-error "Type mismatch in function result" }

o1%ppc => pp1     ! { dg-error "Type mismatch in function result" }
o1%ppc => o2%ppc  ! { dg-error "Type mismatch in function result" }

contains

  real function f1(a,b)    ! { dg-error "Ambiguous interfaces" }
    real,intent(in) :: a,b
    f1 = a + b
  end function

  integer function f2(a,b) ! { dg-error "Ambiguous interfaces" }
    real,intent(in) :: a,b
    f2 = a - b
  end function

end

