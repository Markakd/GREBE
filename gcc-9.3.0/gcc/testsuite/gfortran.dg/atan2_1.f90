! { dg-do run }
! { dg-options "-ffloat-store" }
!
! PR fortran/33197
!
! Check for Fortran 2008's ATAN(Y,X) - which is equivalent
! to Fortran 77's ATAN2(Y,X).
!
integer :: i
real, parameter :: pi4 = 2*acos(0.0)
real, parameter :: pi8 = 2*acos(0.0d0)
do i = 1, 10
  if(atan(1.0,  i/10.0)  -atan2(1.0,  i/10.)    /= 0.0)   STOP 1
  if(atan(1.0d0,i/10.0d0)-atan2(1.0d0,i/10.0d0) /= 0.0d0) STOP 2
end do

! Atan(1,1) = Pi/4
if (abs(atan(1.0,1.0)    -pi4/4.0)   > epsilon(pi4)) STOP 3
if (abs(atan(1.0d0,1.0d0)-pi8/4.0d0) > epsilon(pi8)) STOP 4

! Atan(-1,1) = -Pi/4
if (abs(atan(-1.0,1.0)    +pi4/4.0)   > epsilon(pi4)) STOP 5
if (abs(atan(-1.0d0,1.0d0)+pi8/4.0d0) > epsilon(pi8)) STOP 6

! Atan(1,-1) = 3/4*Pi
if (abs(atan(1.0,-1.0)    -3.0*pi4/4.0)     > epsilon(pi4)) STOP 7
if (abs(atan(1.0d0,-1.0d0)-3.0d0*pi8/4.0d0) > epsilon(pi8)) STOP 8

! Atan(-1,-1) = -3/4*Pi
if (abs(atan(-1.0,-1.0)    +3.0*pi4/4.0)     > epsilon(pi4)) STOP 9
if (abs(atan(-1.0d0,-1.0d0)+3.0d0*pi8/4.0d0) > epsilon(pi8)) STOP 10

! Atan(3,-5) = 2.60117315331920908301906501867... = Pi - 3/2 atan(3/5)
if (abs(atan(3.0,-5.0)    -2.60117315331920908301906501867) > epsilon(pi4)) STOP 11
if (abs(atan(3.0d0,-5.0d0)-2.60117315331920908301906501867d0) > epsilon(pi8)) STOP 12

end
