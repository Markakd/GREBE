/* From PR rtl-optimization/19683.  On little-endian MIPS targets,
   reload would incorrectly inherit the high part of the multiplication
   result.  */
/* { dg-do run { target mips*-*-* } } */

extern void abort (void);
extern void exit (int);

#define REPEAT10(X, Y)					\
  X(Y##0); X(Y##1); X(Y##2); X(Y##3); X(Y##4);		\
  X(Y##5); X(Y##6); X(Y##7); X(Y##8); X(Y##9)

#define REPEAT30(X) REPEAT10 (X, 0); REPEAT10 (X, 1); REPEAT10 (X, 2)
#define IN(X) unsigned int x##X = ptr[0]
#define OUT(X) ptr[0] = x##X

#if __mips_isa_rev <= 5
union u { unsigned long long ll; unsigned int i[2]; };

unsigned int __attribute__ ((nomips16))
foo (volatile unsigned int *ptr)
{
  union u u;
  int result;

  u.ll = (unsigned long long) ptr[0] * ptr[0];
  REPEAT30 (IN);
  REPEAT30 (OUT);
  asm ("#" : "=l" (result) : "l" (u.i[1]));
  return result;
}
#endif

int __attribute__ ((nomips16))
main (void)
{
#if __mips_isa_rev <= 5
  unsigned int array[] = { 1000 * 1000 * 1000 };
  union u u;

  u.ll = (unsigned long long) array[0] * array[0];
  if (foo (array) != u.i[1])
    abort ();
#endif
  exit (0);
}
