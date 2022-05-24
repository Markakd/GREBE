! { dg-do compile } 
! { dg-additional-options "-fopenmp" } 

module test
contains
  subroutine ichi
    implicit none
    integer :: i
    !$acc parallel
    !$omp do ! { dg-error "cannot be specified" }
    do i = 1,5
    enddo
    !$acc end parallel
  end subroutine ichi

  subroutine ni
    implicit none
    integer :: i
    !$omp parallel
    !$acc loop ! { dg-error "cannot be specified" }
    do i = 1,5
    enddo
    !$omp end parallel
  end subroutine ni

  subroutine san
    implicit none
    integer :: i
    !$omp do
    !$acc loop ! { dg-error "Unexpected" }
    do i = 1,5
    enddo
   end subroutine san

   subroutine yon
     implicit none
     integer :: i
     !$acc loop
     !$omp do ! { dg-error "Expected DO loop" }
     do i = 1,5
     enddo
   end subroutine yon

   subroutine go
     implicit none
     integer :: i, j

     !$omp parallel
     do i = 1,5
       !$acc kernels ! { dg-error "cannot be specified" }
       do j = 1,5
       enddo
       !$acc end kernels
     enddo
     !$omp end parallel
   end subroutine go

   subroutine roku
     implicit none

     !$acc data
     !$omp parallel ! { dg-error "cannot be specified" }
     !$omp end parallel
     !$acc end data
   end subroutine roku

   subroutine nana
     !$acc parallel &
     !$omp do ! { dg-error "Wrong OpenACC continuation" }

     !$omp parallel &
     !$acc loop ! { dg-error "Wrong OpenMP continuation" }
   end subroutine nana
end module test
