c { dg-do run }
      DO I = 0, 255
         IF (ICHAR(CHAR(I)) .NE. I) STOP 1
      ENDDO
      END
