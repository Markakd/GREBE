! { dg-do run }     
! { dg-options "-std=legacy" }
!
! Test of fix to bug triggered by NIST fm908.for.
! Left tabbing, followed by X or T-tabbing to the right would
! cause spaces to be overwritten on output data.
! Contributed by Paul Thomas  <pault@gcc.gnu.org>
! PR25349 Revised by Jerry DeLisle <jvdelisle@gcc.gnu.org> 
program tl_editting
  character*10           ::  line, many(5), s
  character*10           ::  aline = "abcdefxyij"
  character*2            ::  bline = "gh"
  character*10           ::  cline = "abcdefghij"

! Character unit test
  write (line, '(a10,tl6,2x,a2)') aline, bline
  if (line.ne.cline) STOP 1

! Character array unit test
  many = "0123456789"
  write(many(1:5:2), '(a10,tl6,2x,a2)') aline, bline, aline, bline, aline,&
  &bline
  if (many(1).ne.cline) STOP 2
  if (many(3).ne.cline) STOP 3
  if (many(5).ne.cline) STOP 4

! File unit test
  write (10, '(a10,tl6,2x,a2)') aline, bline
  rewind(10)
  read(10, '(a)') s
  if (s.ne.cline) STOP 1
  close(10, status='delete')
  
end program tl_editting

