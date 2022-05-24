/* { dg-timeout-factor 4.0 } */
/* { dg-require-effective-target run_expensive_tests } */

#define PAR1 int, int, int, int, int, int, int, int, int, int
#define PAR2 PAR1, PAR1, PAR1, PAR1, PAR1, PAR1, PAR1, PAR1, PAR1, PAR1
#define PAR3 PAR2, PAR2, PAR2, PAR2, PAR2, PAR2, PAR2, PAR2, PAR2, PAR2
#define PAR4 PAR3, PAR3, PAR3, PAR3, PAR3, PAR3, PAR3, PAR3, PAR3, PAR3
#define PAR5 PAR4, PAR4, PAR4, PAR4, PAR4, PAR4, PAR4, PAR4, PAR4, PAR4
#define PAR6 PAR5, PAR5, PAR5, PAR5, PAR5, PAR5, PAR5, PAR5, PAR5, PAR5

extern void func (PAR4);

#define ARG1 0,1,2,3,4,5,6,7,8,9
#define ARG2 ARG1, ARG1, ARG1, ARG1, ARG1, ARG1, ARG1, ARG1, ARG1, ARG1
#define ARG3 ARG2, ARG2, ARG2, ARG2, ARG2, ARG2, ARG2, ARG2, ARG2, ARG2
#define ARG4 ARG3, ARG3, ARG3, ARG3, ARG3, ARG3, ARG3, ARG3, ARG3, ARG3
#define ARG5 ARG4, ARG4, ARG4, ARG4, ARG4, ARG4, ARG4, ARG4, ARG4, ARG4
#define ARG5HALF ARG5, ARG5, ARG5, ARG5, ARG5

void caller(void)
{
  func (ARG4);
}
