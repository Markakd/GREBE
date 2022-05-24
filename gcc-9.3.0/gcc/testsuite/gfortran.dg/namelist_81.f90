! { dg-do run }
! PR56786 Error on embedded spaces
integer :: i(3)
namelist /nml/ i

i = -42
open(99,status='scratch')
write(99,'(a)') '&nml i(3 ) = 5 /'
rewind(99)
read(99,nml=nml)
close(99)
if (i(1)/=-42 .or. i(2)/=-42 .or. i(3)/=5) STOP 1

! Shorten the file so the read hits EOF

open(99,status='scratch')
write(99,'(a)') '&nml i(3 ) = 5 '
rewind(99)
read(99,nml=nml, end=30)
STOP 2
! Shorten some more
 30 close(99)
open(99,status='scratch')
write(99,'(a)') '&nml i(3 ) ='
rewind(99)
read(99,nml=nml, end=40)
STOP 3
! Shorten some more
 40 close(99)
open(99,status='scratch')
write(99,'(a)') '&nml i(3 )'
rewind(99)
read(99,nml=nml, end=50)
STOP 4
! Shorten some more
 50 close(99)
open(99,status='scratch')
write(99,'(a)') '&nml i(3 '
rewind(99)
read(99,nml=nml, end=60)
STOP 5
 60 close(99)
end
