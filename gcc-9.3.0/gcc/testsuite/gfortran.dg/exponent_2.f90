! { dg-do run }
! { dg-options "-fdefault-integer-8" }
! PR fortran/32942
! Testcase contributed by Dominique d'Humieres <dominiq@lps.ens.fr>.
integer i
real x
x = 3.0
if (2 /= exponent(x)) STOP 1
i = exponent (x)
if (i /= 2) STOP 2
end
