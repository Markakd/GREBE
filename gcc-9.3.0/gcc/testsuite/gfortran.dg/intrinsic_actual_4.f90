! { dg-do run }
! Tests the fix for PR27900, in which an ICE would be caused because
! the actual argument LEN had no type.
!
! Contributed by Klaus Ramst�ck <klra67@freenet.de>
!
      subroutine sub (proc, chr)
      external proc
      integer proc
      character*(*) chr
      if (proc (chr) .ne. 6) STOP 1
      end subroutine sub

      implicit none
      integer i
      intrinsic len
      i = len ("123")
      call sub (len, "abcdef")
      end
