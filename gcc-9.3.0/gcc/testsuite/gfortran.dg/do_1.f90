! { dg-do run }
! { dg-options "-Wall" }
! Program to check corner cases for DO statements.
program do_1
  implicit none
  integer i, j

  ! limit=HUGE(i), step > 1
  j = 0
  do i = HUGE(i) - 10, HUGE(i), 2
    j = j + 1
  end do
  if (j .ne. 6) STOP 1
  j = 0
  do i = HUGE(i) - 9, HUGE(i), 2
    j = j + 1
  end do
  if (j .ne. 5) STOP 2

  ! Same again, but unknown loop step
  if (test1(10, 1) .ne. 11) STOP 3
  if (test1(10, 2) .ne. 6) STOP 4
  if (test1(9, 2) .ne. 5) STOP 5

  ! Zero iterations
  j = 0
  do i = 1, 0, 1 ! { dg-warning "executed zero times" }
    j = j + 1
  end do
  if (j .ne. 0) STOP 6
  j = 0
  do i = 1, 0, 2 ! { dg-warning "executed zero times" }
    j = j + 1
  end do
  if (j .ne. 0) STOP 7
  j = 0
  do i = 1, 2, -1 ! { dg-warning "executed zero times" }
    j = j + 1
  end do
  if (j .ne. 0) STOP 8
  call test2 (0, 1)
  call test2 (0, 2)
  call test2 (2, -1)
  call test2 (2, -2)

  ! Bound near smallest value
  j = 0;
  do i = -HUGE(i), -HUGE(i), 10
    j = j + 1
  end do
  if (j .ne. 1) STOP 9
contains
! Returns the number of iterations performed.
function test1(r, step)
  implicit none
  integer test1, r, step
  integer k, n
  k = 0
  do n = HUGE(n) - r, HUGE(n), step
    k = k + 1
  end do
  test1 = k
end function

subroutine test2 (lim, step)
  implicit none
  integer lim, step
  integer k, n
  k = 0
  do n = 1, lim, step
    k = k + 1
  end do
  if (k .ne. 0) STOP 10
end subroutine
end program
