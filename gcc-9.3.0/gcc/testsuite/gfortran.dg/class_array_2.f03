! { dg-do run }
!
! Test functionality of pointer class arrays:
! ALLOCATE with source, ASSOCIATED, DEALLOCATE, passing as arguments for
! ELEMENTAL and non-ELEMENTAL procedures, SELECT TYPE and LOWER/UPPER.
!
  type :: type1
    integer :: i
  end type
  type, extends(type1) :: type2
    real :: r
  end type
  class(type1), pointer, dimension (:) :: x

  allocate(x(2), source = type2(42,42.0))
  call display(x, [1], [2], t2 = [type2(42,42.0),type2(42,42.0)])
  call display(x, [1], [2], t2 = [type2(111,99.0),type2(111,99.0)])
  if (associated (x)) deallocate (x)

  allocate(x(1:4), source = [(type2(i,42.0 + float (i)), i = 1, 4)]) 
  call display(x, [1], [4], t2 = [(type2(i,42.0 + float (i)), i = 1, 4)])
  call display(x, [1], [4], t2 = [(type2(111,99.0), i = 1, 4)])

  if (any (disp (x) .ne. [99.0,99.0,99.0,99.0])) STOP 1

  if (associated (x)) deallocate (x)

  allocate(x(1:4), source = type1(42))
  call display(x, [1], [4], t1 = [(type1(42), i = 1, 4)])
  call display(x, [1], [4], t1 = [type1(42),type1(99),type1(42),type1(42)])
  if (any (disp (x) .ne. [0.0,0.0,0.0,0.0])) STOP 2

  if (associated (x)) deallocate (x)

contains
  subroutine display(x, lower, upper, t1, t2)
    class(type1), pointer, dimension (:) :: x
    integer, dimension (:) :: lower, upper
    type(type1), optional, dimension(:) :: t1
    type(type2), optional, dimension(:) :: t2
    select type (x)
      type is (type1)
        if (present (t1)) then
          if (any (x%i .ne. t1%i)) STOP 3
        else
          STOP 4
        end if
        x(2)%i = 99
      type is (type2)
        if (present (t2)) then
          if (any (x%i .ne. t2%i)) STOP 5
          if (any (x%r .ne. t2%r)) STOP 6
        else
          STOP 7
        end if
        x%i = 111
        x%r = 99.0
    end select
    call bounds (x, lower, upper)
  end subroutine
  subroutine bounds (x, lower, upper)
    class(type1), pointer, dimension (:) :: x
    integer, dimension (:) :: lower, upper
    if (any (lower .ne. lbound (x))) STOP 8
    if (any (upper .ne. ubound (x))) STOP 9
  end subroutine
  elemental function disp(y) result(ans)
    class(type1), intent(in) :: y
    real :: ans
    select type (y)
      type is (type1)
        ans = 0.0
      type is (type2)
        ans = y%r
    end select
  end function
end

