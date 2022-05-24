! PR fortran/15080
! Really test forall with temporary
program evil_forall
  implicit none
  type t
    logical valid
    integer :: s
    integer, dimension(:), pointer :: p
  end type
  type (t), dimension (5) :: v
  integer i

  allocate (v(1)%p(2))
  allocate (v(2)%p(8))
  v(3)%p => NULL()
  allocate (v(4)%p(8))
  allocate (v(5)%p(2))

  v(:)%valid = (/.true., .true., .false., .true., .true./)
  v(:)%s = (/1, 8, 999, 6, 2/)
  v(1)%p(:) = (/9, 10/)
  v(2)%p(:) = (/1, 2, 3, 4, 5, 6, 7, 8/)
  v(4)%p(:) = (/13, 14, 15, 16, 17, 18, 19, 20/)
  v(5)%p(:) = (/11, 12/)


  forall (i=1:5,v(i)%valid)
    v(i)%p(1:v(i)%s) = v(6-i)%p(1:v(i)%s)
  end forall

  if (any(v(1)%p(:) .ne. (/11, 10/))) STOP 1
  if (any(v(2)%p(:) .ne. (/13, 14, 15, 16, 17, 18, 19, 20/))) STOP 2
  if (any(v(4)%p(:) .ne. (/1, 2, 3, 4, 5, 6, 19, 20/))) STOP 3
  if (any(v(5)%p(:) .ne. (/9, 10/))) STOP 4

  ! I should really free the memory I've allocated.
end program
