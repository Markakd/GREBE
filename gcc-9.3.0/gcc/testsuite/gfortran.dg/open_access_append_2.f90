! { dg-do run }
! Testcase for the GNU extension OPEN(...,ACCESS="APPEND")
  open (10,err=900,access="append",position="asis") ! { dg-warning "Extension: ACCESS specifier in OPEN statement" }
  STOP 1
 900 end
! { dg-output ".*Extension.*" }
