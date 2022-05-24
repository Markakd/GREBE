! { dg-do run }
! Test procedures with allocatable dummy arguments
program alloc_dummy

    implicit none
    integer, allocatable :: a(:)
    integer, allocatable :: b(:)

    call init(a)
    if (.NOT.allocated(a)) STOP 1
    if (.NOT.all(a == [ 1, 2, 3 ])) STOP 2

    call useit(a, b)
    if (.NOT.all(b == [ 1, 2, 3 ])) STOP 3

    if (.NOT.all(whatever(a) == [ 1, 2, 3 ])) STOP 4

    call kill(a)
    if (allocated(a)) STOP 5

    call kill(b)
    if (allocated(b)) STOP 6

contains

    subroutine init(x)
        integer, allocatable, intent(out) :: x(:)
        allocate(x(3))
        x = [ 1, 2, 3 ]
    end subroutine init

    subroutine useit(x, y)
        integer, allocatable, intent(in)  :: x(:)
        integer, allocatable, intent(out) :: y(:)
        if (allocated(y)) STOP 7
        call init(y)
        y = x
    end subroutine useit

    function whatever(x)
        integer, allocatable :: x(:)
        integer :: whatever(size(x))
        
        whatever = x
    end function whatever

    subroutine kill(x)
        integer, allocatable, intent(out) :: x(:)
    end subroutine kill

end program alloc_dummy
