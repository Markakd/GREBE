! { dg-do run }
!
! PR fortran/61881
! PR fortran/61888
!
!
use iso_c_binding
implicit none

call dim0(5, 4)

call dim1([1, 2, 3], 4*3)

call dimd(5, 4)
call dimd([1, 2, 3], 4*3)
call dimd(reshape([1, 4, 2, 3],[2, 2]), 4*4)

call tdim1([1, 2, 3], 4*3)
call tdim1([1_8, 2_8, 3_8], 8*3)

call tdimd(5, 4)
call tdimd([1, 2, 3], 4*3)
call tdimd(reshape([1, 4, 2, 3], [2, 2]), 4*4)
call tdimd(5_8, 8)
call tdimd([1_8, 2_8, 3_8], 8*3)
call tdimd(reshape([1_8, 4_8, 2_8, 3_8],[2,2]), 8*4)

call cdim0(5, 4)

call cdim1([1, 2, 3], 4*3)

call cdimd(5, 4)
call cdimd([1, 2, 3], 4*3)
call cdimd(reshape([1,4,2,3],[2,2]), 4*4)
call cdimd(5_8, 8)
call cdimd([1_8, 2_8, 3_8], 8*3)
call cdimd(reshape([1_8, 4_8, 2_8, 3_8], [2, 2]), 8*4)

contains

subroutine dim0(x, expected_size)
  integer :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 1
  if (storage_size(x)/8 /= expected_size) STOP 2
end

subroutine dim1(x, expected_size)
  integer, dimension(:) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 3
  if (storage_size(x)/8*size(x) /= expected_size) STOP 4
end

subroutine dimd(x, expected_size)
  integer, dimension(..) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 5
  if (storage_size(x)/8*size(x) /= expected_size) STOP 6
end

subroutine cdim0(x, expected_size)
  class(*) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 7
  if (storage_size(x)/8 /= expected_size) STOP 8
end

subroutine cdim1(x, expected_size)
  class(*), dimension(:) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 9
  if (storage_size(x)/8*size(x) /= expected_size) STOP 10
end

subroutine cdimd(x, expected_size)
  class(*), dimension(..) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 11
  if (storage_size(x)/8*size(x) /= expected_size) STOP 12
end

subroutine tdim1(x, expected_size)
  type(*), dimension(:) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 13
end

subroutine tdimd(x, expected_size)
  type(*), dimension(..) :: x
  integer, value :: expected_size
  if (sizeof(x) /= expected_size) STOP 14
end

end
