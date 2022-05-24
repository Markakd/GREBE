! { dg-do run }
! PR28354 Incorrect rounding of .99999 with f3.0 format specifier
! PR30910 ES format not quite right...
! Test case derived from PR. Submitted by Jerry DeLisle <jvdelisle@gcc.gnu.org>
  write(*,50) 0.99999
  write(*,50) -0.99999
  write(*,50) -9.0
  write(*,50) -0.99
  write(*,50) -0.999
  write(*,50) -0.999
  write(*,50) -0.59
  write(*,50) -0.49
  write(*,100) 37.99999
  write(*,100) 10345.0
  write(*,100) 333.678
  write(*,100) 333.499
  50   format(f3.0,"<")
 100   format(f8.0,"<")
  write(6,'(es6.0)') 1.0e-1
  write(*,150) -0.99999
  write(*,150) 0.99999
  write(*,150) -9.0
  write(*,150) -0.99
  write(*,150) -0.999
  write(*,150) -0.999
  write(*,150) -0.59
  write(*,150) -0.49
  write(*,200) 37.99999
  write(*,200) 10345.0
  write(*,200) 333.678
  write(*,200) 333.499
 150   format(es7.0,"<")
 200   format(es8.0,"<")
  write(*,250) -0.99999
  write(*,250) 0.99999
  write(*,250) -9.0
  write(*,250) -0.99
  write(*,250) -0.999
  write(*,250) -0.999
  write(*,250) -0.59
  write(*,250) -0.49
  write(*,300) 37.99999
  write(*,300) 10345.0
  write(*,300) 333.678
  write(*,300) 333.499
 250   format(1pe7.0,"<")
 300   format(1pe6.0,"<")
  end
! { dg-output " 1\\.<(\n|\r\n|\r)" }
! { dg-output "-1\\.<(\n|\r\n|\r)" }
! { dg-output "-9\\.<(\n|\r\n|\r)" }
! { dg-output "-1\\.<(\n|\r\n|\r)" }
! { dg-output "-1\\.<(\n|\r\n|\r)" }
! { dg-output "-1\\.<(\n|\r\n|\r)" }
! { dg-output "-1\\.<(\n|\r\n|\r)" }
! { dg-output "-0\\.<(\n|\r\n|\r)" }
! { dg-output "     38\\.<(\n|\r\n|\r)" }
! { dg-output "  10345\\.<(\n|\r\n|\r)" }
! { dg-output "    334\\.<(\n|\r\n|\r)" }
! { dg-output "    333\\.<(\n|\r\n|\r)" }
! { dg-output "1\\.E-01(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output " 1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-9\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-6\\.E-01<(\n|\r\n|\r)" }
! { dg-output "-5\\.E-01<(\n|\r\n|\r)" }
! { dg-output "  4\\.E\\+01<(\n|\r\n|\r)" }
! { dg-output "  1\\.E\\+04<(\n|\r\n|\r)" }
! { dg-output "  3\\.E\\+02<(\n|\r\n|\r)" }
! { dg-output "  3\\.E\\+02<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output " 1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-9\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-1\\.E\\+00<(\n|\r\n|\r)" }
! { dg-output "-6\\.E-01<(\n|\r\n|\r)" }
! { dg-output "-5\\.E-01<(\n|\r\n|\r)" }
! { dg-output "4\\.E\\+01<(\n|\r\n|\r)" }
! { dg-output "1\\.E\\+04<(\n|\r\n|\r)" }
! { dg-output "3\\.E\\+02<(\n|\r\n|\r)" }
! { dg-output "3\\.E\\+02<(\n|\r\n|\r)" }
