c { dg-do compile }
      SUBROUTINE MIST(N, BETA)
      IMPLICIT REAL(kind=8) (A-H,O-Z)
      INTEGER  IA, IQ, M1
      DIMENSION BETA(N)
      DO 80 IQ=1,M1
         IF (BETA(IQ).EQ.0.0D0) GO TO 120
   80 CONTINUE
  120 IF (IQ.NE.1) GO TO 160
  160 M1 = IA(IQ)
      RETURN
      END
