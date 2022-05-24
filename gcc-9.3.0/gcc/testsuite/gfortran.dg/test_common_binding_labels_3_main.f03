! { dg-do compile }
! { dg-compile-aux-modules "test_common_binding_labels_3.f03" }
module test_common_binding_labels_3_main
  use, intrinsic :: iso_c_binding, only: c_int
  integer(c_int), bind(c, name="my_common_block") :: my_int ! { dg-error "COMMON block at .1. with binding label 'my_common_block' uses the same global identifier as entity at .2." }
end module test_common_binding_labels_3_main

program main
  use test_common_binding_labels_3_main
  use test_common_binding_labels_3 ! { dg-error "COMMON block at .1. with binding label 'my_common_block' uses the same global identifier as entity at .2." }
end program main
