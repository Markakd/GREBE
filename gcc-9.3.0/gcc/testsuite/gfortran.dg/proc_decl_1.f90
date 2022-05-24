! { dg-do compile }
! { dg-options "-std=legacy" }
!
! This tests various error messages for PROCEDURE declarations.
! Contributed by Janus Weil <jaydub66@gmail.com>

module m

  abstract interface
    subroutine sub()
    end subroutine
    subroutine sub2() bind(c)
    end subroutine
  end interface

  procedure(), public, private :: a  ! { dg-error "was already specified" }
  procedure(sub),bind(C) :: a2  ! { dg-error "requires an interface with BIND.C." }
  procedure(sub2), public, bind(c, name="myEF") :: e, f  ! { dg-error "Multiple identifiers provided with single NAME= specifier" }
  procedure(sub2), bind(C, name=""), pointer :: g  ! { dg-error "may not have POINTER attribute" }

  public:: h
  procedure(),public:: h  ! { dg-error "was already specified" }

contains

  subroutine abc
    procedure() :: abc2
  entry abc2(x)  ! { dg-error "PROCEDURE attribute conflicts with ENTRY attribute" }
    real x
  end subroutine

end module m

program prog

  interface z
    subroutine z1()
    end subroutine
    subroutine z2(a)
      integer :: a
    end subroutine
  end interface

  procedure(z) :: bar   ! { dg-error "may not be generic" }

  procedure(), allocatable:: b  ! { dg-error "PROCEDURE attribute conflicts with ALLOCATABLE attribute" }
  procedure(), save:: c  ! { dg-error "PROCEDURE attribute conflicts with SAVE attribute" }

  procedure(dcos) :: my1
  procedure(amax0) :: my2  ! { dg-error "not allowed in PROCEDURE statement" }

  real f, x
  f(x) = sin(x**2)
  external oo

  procedure(f) :: q  ! { dg-error "may not be a statement function" }
  procedure(oo) :: p  ! { dg-error "must be explicit" }

  procedure ( ) :: r 
  procedure ( up ) :: s  ! { dg-error "must be explicit" }

  procedure(t) :: t  ! { dg-error "may not be used as its own interface" }

  call s

contains

  subroutine foo(a,c)  ! { dg-error "PROCEDURE attribute conflicts with INTENT attribute" }
    abstract interface
      subroutine b() bind(C)
      end subroutine b
    end interface
    procedure(b), bind(c,name="hjj") :: a  ! { dg-error "may not have BIND.C. attribute with NAME" }
    procedure(b),intent(in):: c
  end subroutine foo 

end program
