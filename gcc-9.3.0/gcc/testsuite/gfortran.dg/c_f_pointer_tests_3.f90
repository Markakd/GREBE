! { dg-do compile }
! { dg-options "-O2 -fdump-tree-original" }
!
! PR fortran/32600 c_f_pointer w/o shape
! PR fortran/32580 c_f_procpointer
!
! Verify that c_f_prointer [w/o shape] and c_f_procpointer generate
! the right code - and no library call

program test
  use iso_c_binding
  implicit none
  type(c_ptr)    :: cptr
  type(c_funptr) :: cfunptr
  integer(4), pointer :: fptr
  integer(4), pointer :: fptr_array(:)
  procedure(integer(4)), pointer :: fprocptr

  call c_f_pointer(cptr, fptr)
  call c_f_pointer(cptr, fptr_array, [ 1 ])
  call c_f_procpointer(cfunptr, fprocptr)
end program test

! Make sure there is no function call:
! { dg-final { scan-tree-dump-times "c_f" 0 "original" } }
! { dg-final { scan-tree-dump-times "c_f_pointer" 0 "original" } }
! { dg-final { scan-tree-dump-times "c_f_pointer_i4" 0 "original" } }
!
! Check scalar c_f_pointer
! { dg-final { scan-tree-dump-times "  fptr = .integer.kind=4. .. cptr" 1 "original" } }
!
! Array c_f_pointer:
!
! { dg-final { scan-tree-dump-times " fptr_array.data = cptr;" 1 "original" } }
! { dg-final { scan-tree-dump-times " fptr_array.dim\\\[S..\\\].lbound = 1;" 1 "original" } }
! { dg-final { scan-tree-dump-times " fptr_array.dim\\\[S..\\\].ubound = " 1 "original" } }
! { dg-final { scan-tree-dump-times " fptr_array.dim\\\[S..\\\].stride = " 1 "original" } }
!
! Check c_f_procpointer
! { dg-final { scan-tree-dump-times "  fprocptr = .integer.kind=4. .\\*<.*>. ... cfunptr;" 1 "original" } }
!
