! { dg-do compile }
program fc011
! Tests fix for PR20779 and PR20891.
! Submitted by Walt Brainerd, The Fortran Company
! and by Joost VandeVondele  <jv244@cam.ac.uk> 

! This program violates requirements of 6.3.1 of the F95 standard.

! An allocate-object, or a subobject of an allocate-object, shall not appear
! in a bound in the same ALLOCATE statement. The stat-variable shall not appear
! in a bound in the same ALLOCATE statement.

! The stat-variable shall not be allocated within the ALLOCATE statement in which
! it appears; nor shall it depend on the value, bounds, allocation status, or
! association status of any allocate-object or subobject of an allocate-object
! allocated in the same statement.

  integer, pointer :: PTR
  integer, allocatable :: ALLOCS(:)

  allocate (PTR, stat=PTR) ! { dg-error "in the same ALLOCATE statement" }

  allocate (ALLOCS(10),stat=ALLOCS(1)) ! { dg-error "in the same ALLOCATE statement" }

  ALLOCATE(PTR,ALLOCS(PTR)) ! { dg-error "same ALLOCATE statement" }

  deallocate(ALLOCS(1)) ! { dg-error "must be ALLOCATABLE or a POINTER" }

  print *, 'This program has four errors', PTR, ALLOC(1)

end program fc011
