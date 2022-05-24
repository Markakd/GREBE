!{ dg-do run }
! Tests namelist io for an explicit shape array with negative bounds
! provided by Paul Thomas - pault@gcc.gnu.org

program namelist_20
  integer, dimension (-4:-2) :: x
  integer                    :: i, ier
  namelist /a/ x

  open (10, status = "scratch")
  write (10, '(A)') "&a x(-5)=0 /"            !-ve index below lbound
  write (10, '(A)') "&a x(-1)=0 /"            !-ve index above ubound
  write (10, '(A)') "&a x(1:2)=0 /"           !+ve indices
  write (10, '(A)') "&a x(-4:-2)= -4,-3,-2 /" !correct
  write (10, '(A)') " "
  rewind (10)

  ier=0
  read(10, a, iostat=ier)
  if (ier == 0) STOP 1
  ier=0
  read(10, a, iostat=ier)
  if (ier == 0) STOP 2
  ier=0
  read(10, a, iostat=ier)
  if (ier == 0) STOP 3

  ier=0
  read(10, a, iostat=ier)
  if (ier /= 0) STOP 4
  do i = -4,-2
    if (x(i) /= i) STOP 5
  end do

end program namelist_20 
