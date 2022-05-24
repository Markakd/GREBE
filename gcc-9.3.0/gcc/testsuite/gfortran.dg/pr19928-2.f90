! Related to PR 19928.  Check that foo() is only called once per statement.
! { dg-do run }
program main
  implicit none
  type t
    integer, dimension (5) :: field
  end type t
  type (t), dimension (2) :: a
  integer :: calls, i, j

  forall (i = 1:2, j = 1:5) a(i)%field(j) = i * 100 + j
  calls = 0
  if (sum (a%field(foo(calls))) .ne. 304) STOP 1
  if (calls .ne. 1) STOP 2
  if (sum (a(foo(calls))%field) .ne. 1015) STOP 3
  if (calls .ne. 2) STOP 4
contains
  function foo (calls)
    integer :: calls, foo
    calls = calls + 1
    foo = 2
  end function foo 
end program main
