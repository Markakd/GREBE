! { dg-do compile }
! PR 30452 - this used to cause syntax errors due to the presence,
!            as characters, of bytes 0xfe and 0xff.
program main
  if (char (254) /= "�") STOP 1
  if (char (255) /= "�") STOP 2
end program main
