C Test case for PR/9258
C Origin: kmccarty@princeton.edu
C
C { dg-do compile }
      SUBROUTINE FOO (B)

  10  CALL BAR (A)
      ASSIGN 20 TO M           !{ dg-warning "Deleted feature: ASSIGN" }
      IF (100.LT.A) GOTO 10
      GOTO 40
C
  20  IF (B.LT.ABS(A)) GOTO 10
      ASSIGN 30 TO M           !{ dg-warning "Deleted feature: ASSIGN" }
      GOTO 40
C
  30  ASSIGN 10 TO M           !{ dg-warning "Deleted feature: ASSIGN" }
  40  GOTO M,(10,20,30)        !{ dg-warning "Deleted feature: Assigned GOTO" }
      END
