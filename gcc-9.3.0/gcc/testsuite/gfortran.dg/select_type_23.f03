! { dg-do compile }
!
! PR 48699: [OOP] MOVE_ALLOC inside SELECT TYPE
!
! Contributed by Salvatore Filippone <sfilippone@uniroma2.it>
!
! Updated for PR fortran/48887

program testmv2

  type bar
    integer, allocatable  :: ia(:), ja(:)
  end type bar

  class(bar), allocatable :: sm,sm2

  allocate(sm2)

  select type(sm2) 
  type is (bar)
    call move_alloc(sm2,sm) ! { dg-error "must be ALLOCATABLE" }
  end select

end program testmv2
