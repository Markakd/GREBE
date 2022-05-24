! { dg-do run }
! { dg-options "-std=legacy" }
!
!pr19313 - inquire(..pad=..)
      implicit none
!     logical debug
!     data debug /.TRUE./
      character*20 chr
      chr=''
!  not connected 
      inquire(7,pad=chr)
!     if (debug) print*,chr
      if (chr.ne.'UNDEFINED') STOP 1
      chr=''
!  not a formatted file
      open(7,FORM='UNFORMATTED',STATUS='SCRATCH')
      inquire(7,pad=chr)
!     if (debug) print*,chr
      if (chr.ne.'UNDEFINED') STOP 2
      chr=''
! yes
      open(8,STATUS='SCRATCH',PAD='YES')
      inquire(8,pad=chr)
!     if (debug) print*,chr
      if (chr.ne.'YES') STOP 3
      chr=''
! no
      open(9,STATUS='SCRATCH',PAD='NO')
      inquire(9,pad=chr)
!     if (debug) print*,chr
      if (chr.ne.'NO') STOP 4
      chr=''
      end
