! { dg-do run }
! { dg-options "-std=legacy" }
!
! pr 16597
! libgfortran
! reading a direct access record after it was written did
! not always return the correct data.

      program gfbug4
      implicit none

      integer      strlen
      parameter    (strlen = 4)

      integer      iunit 
      character    string *4

      iunit = 99
      open (UNIT=iunit,FORM='unformatted',ACCESS='direct',RECL=strlen)
      write (iunit, rec=1) 'ABCD'
      read (iunit, rec=1) string
      close (iunit, status = 'delete')
      if (string.ne.'ABCD') STOP 1

      open (UNIT=iunit,FORM='unformatted',ACCESS='direct',STATUS='scratch',RECL=strlen)
      write (iunit, rec=1) 'ABCD'
      read (iunit, rec=1) string
      close (iunit)
      if (string.ne.'ABCD') STOP 2
      end
