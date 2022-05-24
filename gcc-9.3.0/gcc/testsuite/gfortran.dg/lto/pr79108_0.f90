! { dg-lto-do link }
! { dg-require-effective-target lto_incremental }
! { dg-lto-options {{ -Ofast -flto --param ggc-min-expand=0 --param ggc-min-heapsize=0 }} }
! { dg-extra-ld-options "-r" }

MODULE Errorcheck_mod
CONTAINS
SUBROUTINE Check_open(ios, outputstr, errortype)
character(len=*), intent(in) :: outputstr
if (ios > 0 .AND. errortype == FATAL) then
  write(*,*) 'The value of ios was:', ios
end if
END SUBROUTINE Check_open
END MODULE Errorcheck_mod

