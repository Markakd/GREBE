! { dg-do run }
! PR libfortran/20480
! fxcoudert@gcc.gnu.org
  character(len=80) c
  write (c,'(ES12.3)') 0.0
  if (trim(adjustl(c)) .ne. '0.000E+00') STOP 1
  write (c,'(EN12.3)') 0.0
  if (trim(adjustl(c)) .ne. '0.000E+00') STOP 2
  end
