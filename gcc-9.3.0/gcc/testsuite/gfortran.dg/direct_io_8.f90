! { dg-do run }
! PR 34594 - this used to give runtime errors due to an
! end condition.
program main
  implicit none
  integer :: iou, i, ir, TEMP_CHANGES
  i=44
  ir = -42

  open(11,file="foo_direct_io_8.dat")
  ! Try a direct access read on a formatted sequential rile
  READ (11, REC = I, ERR = 99) TEMP_CHANGES
  STOP 1
99 continue
  ! Variant 2: ir is ok, but does not jump to 99
  READ (11, REC = I, IOSTAT = IR, ERR = 98) TEMP_CHANGES
  STOP 2

98 continue
  if(ir == 0) then
     STOP 3
  end if
  close(11,status="delete")
end program main

