! { dg-do compile }
! { dg-options "-Wc-binding-type" }
module c_kind_tests_2
  use, intrinsic :: iso_c_binding

  integer, parameter :: myF = c_float
  real(myF), bind(c) :: myCFloat
  integer(myF), bind(c) :: myCInt       ! { dg-warning "is for type REAL" }
  integer(c_double), bind(c) :: myCInt2 ! { dg-warning "is for type REAL" }

  integer, parameter :: myI = c_int
  real(myI) :: myReal             ! { dg-warning "is for type INTEGER" }
  real(myI), bind(c) :: myCFloat2 ! { dg-warning "is for type INTEGER" }
  real(4), bind(c) :: myFloat     ! { dg-warning "may not be a C interoperable" }
end module c_kind_tests_2
