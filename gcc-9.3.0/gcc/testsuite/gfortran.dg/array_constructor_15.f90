! { dg-do compile }
! { dg-options "-O2 -fdump-tree-original" }
  integer :: x(2,2)
  if (any(x(:,:) .ne. reshape ((/ 3, 1, 4, 1 /), (/ 2, 2 /)))) STOP 1
end
! { dg-final { scan-tree-dump-times "atmp" 0 "original" } }
