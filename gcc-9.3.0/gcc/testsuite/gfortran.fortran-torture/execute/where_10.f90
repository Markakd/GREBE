! Check whether conditional ELSEWHEREs work
! (with final unconditional ELSEWHERE)
program where_10
   integer :: a(5)
   integer :: b(5)

   a = (/1, 2, 3, 4, 5/)
   b = (/0, 0, 0, 0, 0/)
   where (a .eq. 1)
     b = 3
   elsewhere (a .eq. 2)
     b = 1
   elsewhere (a .eq. 3)
     b = 4
   elsewhere (a .eq. 4)
     b = 1
   elsewhere
     b = 5
   endwhere
   if (any (b .ne. (/3, 1, 4, 1, 5/))) &
     STOP 1
end program

