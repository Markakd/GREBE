! { dg-do compile }
! { dg-options "-Wc-binding-type" }
module interop_params
use, intrinsic :: iso_c_binding

type my_f90_type
   integer :: i
   real :: x
end type my_f90_type

contains
  subroutine test_0(my_f90_int) bind(c) ! { dg-warning "may not be C interoperable" }
    use, intrinsic :: iso_c_binding
    integer, value :: my_f90_int 
  end subroutine test_0

  subroutine test_1(my_f90_real) bind(c)
    real(c_int), value :: my_f90_real    ! { dg-warning "is for type INTEGER" }
  end subroutine test_1

  subroutine test_2(my_type) bind(c) ! { dg-error "is not C interoperable" }
    use, intrinsic :: iso_c_binding
    type(my_f90_type) :: my_type 
  end subroutine test_2
end module interop_params
