! { dg-do run }
! tests basic block data functionality
! we didn't allow multiple block data program units
block data 
 common /a/ y(3)
 data y /3*1./
end

blockdata d1
 common /a/ w(3)
 common /b/ u
 data u /1./
end blockdata d1

block data d2
 common /b/ u
 common j ! { dg-warning "blank COMMON but initialization is only allowed in named common" }
 data j /1/
end block data d2
!
! begin testing code
common /a/ x(3)
common /b/ y
common i

if (any(x /= 1.)) STOP 1
if (y /= 1. .or. i /= 1) STOP 2
end
