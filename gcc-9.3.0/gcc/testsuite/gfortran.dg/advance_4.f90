! { dg-do run }
! PR31207 Last record truncated for read after short write
program main
  character(10) :: answer
  write (12,'(A,T2,A)',advance="no") 'XXXXXX','ABCD'
  close (12)
  read (12, '(6A)') answer
  close (12, status="delete")
  if (answer /= "XABCDX") STOP 1
end program main
