! { dg-do run }
! Check that [...] style array constructors work
program bracket_array_constructor
    implicit none
    integer :: a(4), i

    a = [ 1, 2, 3, 4 ]
    do i = 1, size(a)
        if (a(i) /= i) STOP 1
    end do

    a = [ (/ 1, 2, 3, 4 /) ]
    do i = 1, size(a)
        if (a(i) /= i) STOP 2
    end do

end program bracket_array_constructor
