! { dg-do compile }
! { dg-options "-Wc-binding-type" }
module bind_c_implicit_vars

bind(c) :: j ! { dg-warning "may not be C interoperable" }

contains
  subroutine sub0(i) bind(c) ! { dg-warning "may not be C interoperable" }
    i = 0
  end subroutine sub0
end module bind_c_implicit_vars
