! { dg-do run }
! PR27304 Test running out of data descriptors with data remaining.
! Derived from case in PR.  Submitted by Jerry DeLisle <jvdelisle@gcc.gnu.org>.
      program test
      implicit none
      integer :: n
      n = 1
      open(10, status="scratch")
      write(10,"(i7,(' abcd'))", err=10) n, n
      STOP 1
 10   close(10)
      end program test
