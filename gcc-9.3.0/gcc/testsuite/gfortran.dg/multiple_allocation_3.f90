! { dg-do run }
! PR 49755 - If allocating an already allocated array, and stat=
!            is given, set stat to non zero and do not touch the array.
program test
    integer, allocatable :: A(:, :)
    integer :: stat

    allocate(A(20,20))
    A = 42

    ! Allocate of already allocated variable
    allocate (A(5,5), stat=stat)

    ! Expected: Error stat and previous allocation status
    if (stat == 0) STOP 1
    if (any (shape (A) /= [20, 20])) STOP 2
    if (any (A /= 42)) STOP 3
end program

