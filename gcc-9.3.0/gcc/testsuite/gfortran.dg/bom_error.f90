��print *, "Hello world!"
��end ! { dg-error "Invalid character" }
! { dg-do compile }
! { dg-error "Unexpected end of file" "" { target "*-*-*" } 0 }
