! { dg-do run }
! { dg-options "-O -fdump-tree-original" }
program main
  implicit none
  character(len=4) :: c
  integer :: n
  integer :: i
  common /foo/ i

  n = 0
  i = 0
  c = 'abcd'
  if ('a ' // c == 'a' // c) STOP 1
  if ('a' // c == 'a ' // c) STOP 2
end program main

! { dg-final { scan-tree-dump-times "gfortran_concat_string" 4 "original" } }
! { dg-final { scan-tree-dump-times "gfortran_compare_string" 2 "original" } }

