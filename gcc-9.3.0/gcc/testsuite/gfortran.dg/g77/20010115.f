c { dg-do compile }
* GNATS PR Fortran/1636
      PRINT 42, 'HELLO'
   42 FORMAT(A)
      CALL WORLD
      END
      SUBROUTINE WORLD
      PRINT 42, 'WORLD'
   42 FORMAT(A)
      END
