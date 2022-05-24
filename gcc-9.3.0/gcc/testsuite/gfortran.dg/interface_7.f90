! { dg-do compile }
! One of the tests of the patch for PR30068.
!  Taken from the fortran 2003 standard C11.2.
!
! The interface is invalid although it is unambiguous because the
! standard explicitly does not require recursion into the formal
! arguments of procedures that themselves are interface arguments.
!
module xx
  INTERFACE BAD9
    SUBROUTINE S9A(X)
      REAL :: X
    END SUBROUTINE S9A
    SUBROUTINE S9B(X)     ! { dg-error "Ambiguous interfaces" }
      INTERFACE
        FUNCTION X(A)
          REAL :: X,A
        END FUNCTION X
      END INTERFACE
    END SUBROUTINE S9B
    SUBROUTINE S9C(X)     ! { dg-error "Ambiguous interfaces" }
      INTERFACE
        FUNCTION X(A)
          REAL :: X
          INTEGER :: A
        END FUNCTION X
      END INTERFACE
    END SUBROUTINE S9C
  END INTERFACE BAD9
end module xx
