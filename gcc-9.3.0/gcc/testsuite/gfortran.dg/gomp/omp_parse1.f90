! { dg-do compile }
! { dg-options "-fopenmp -fdump-tree-omplower" }
  !$omp  parallel
call bar
	!$omp end parallel
  !$omp 	 	p&
!$omp&arallel
call bar
!$omp e&
!$omp&ndparallel
!$omp  &
!$omp  &  &
!$omp pa&
!$omp rallel
call bar
!$omp end parallel
end

! { dg-final { scan-tree-dump-times "pragma omp parallel" 3 "omplower" } }
