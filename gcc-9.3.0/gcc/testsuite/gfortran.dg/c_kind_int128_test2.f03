! { dg-do run }
! { dg-options "-std=gnu" }
! { dg-require-effective-target fortran_integer_16 }
!
! Note: int_fast128_t currently not supported.

program c_kind_int128
  use, intrinsic :: iso_c_binding
  integer(c_int128_t) :: a  
  integer(c_int_least128_t) :: b  
! integer(c_int_fast128_t) :: c
    
  if (sizeof (a) /= 16) STOP 1
  if (sizeof (b) /= 16) STOP 2
!  if (sizeof (c) /= 16) STOP 3
end program c_kind_int128
