/* Copyright (C) 2009  Free Software Foundation.

   Verify that folding of complex mul and div work correctly.
   TI C6X specific version, reduced by two tests that fails due to the
   use of implicit -freciprocal-math.

   Origin: Kaveh R. Ghazi,  August 13, 2009.  */

/* { dg-do run } */
/* { dg-options "-O2" } */
/* { dg-add-options ieee } */

extern void link_error(int);

/* Evaluate this expression at compile-time.  */
#define COMPILETIME_TESTIT(TYPE,X,OP,Y,RES) do { \
  if ((_Complex TYPE)(X) OP (_Complex TYPE)(Y) != (_Complex TYPE)(RES)) \
    link_error(__LINE__); \
} while (0)

/* Use this error function for cases which only evaluate at
   compile-time when optimizing.  */
#ifdef __OPTIMIZE__
# define ERROR_FUNC(X) link_error(X)
#else
# define ERROR_FUNC(X) __builtin_abort()
#endif

/* Evaluate this expression at compile-time using static initializers.  */
#define STATICINIT_TESTIT(TYPE,X,OP,Y,RES) do { \
  static const _Complex TYPE foo = (_Complex TYPE)(X) OP (_Complex TYPE)(Y); \
  if (foo != (_Complex TYPE)(RES)) \
    ERROR_FUNC (__LINE__); \
} while (0)

/* Evaluate this expression at runtime.  */
#define RUNTIME_TESTIT(TYPE,X,OP,Y,RES) do { \
  volatile _Complex TYPE foo; \
  foo = (_Complex TYPE)(X); \
  foo OP##= (_Complex TYPE)(Y); \
  if (foo != (_Complex TYPE)(RES)) \
    __builtin_abort(); \
} while (0)

/* Evaluate this expression at compile-time and runtime.  */
#define TESTIT(TYPE,X,OP,Y,RES) do { \
  STATICINIT_TESTIT(TYPE,X,OP,Y,RES); \
  COMPILETIME_TESTIT(TYPE,X,OP,Y,RES); \
  RUNTIME_TESTIT(TYPE,X,OP,Y,RES); \
} while (0)

/* Either the real or imaginary parts should be infinity.  */
#define TEST_ONE_PART_INF(VAL) do { \
  static const _Complex double foo = (VAL); \
  if (! __builtin_isinf(__real foo) && ! __builtin_isinf(__imag foo)) \
    ERROR_FUNC (__LINE__); \
  if (! __builtin_isinf(__real (VAL)) && ! __builtin_isinf(__imag (VAL))) \
    __builtin_abort(); \
} while (0)

int main()
{
  /* Test some regular finite values.  */
  TESTIT (double, 3.+4.i, *, 2, 6+8i);
  TESTIT (double, 3.+4.i, /, 2, 1.5+2i);
  TESTIT (int, 3+4i, *, 2, 6+8i);
  TESTIT (int, 3+4i, /, 2, 1+2i);

  TESTIT (double, 3.+4.i, *, 2+5i, -14+23i);
  TESTIT (int, 3+4i, *, 2+5i, -14+23i);
  TESTIT (int, 30+40i, /, 5i, 8-6i);
  TESTIT (int, 14+6i, /, 7+3i, 2);
  TESTIT (int, 8+24i, /, 4+12i, 2);

  /* Test for accuracy.  */
  COMPILETIME_TESTIT (double,
		      (1 + __DBL_EPSILON__ + 1i),
		      *,
		      (1 - __DBL_EPSILON__ + 1i),
		      -4.93038065763132378382330353301741393545754021943139377981e-32+2i);

  /* This becomes (NaN + iInf).  */
#define VAL1 ((_Complex double)__builtin_inf() * 1i)

  /* Test some C99 Annex G special cases.  */
  TEST_ONE_PART_INF ((VAL1) * (VAL1));
  TEST_ONE_PART_INF ((_Complex double)1 / (_Complex double)0);
  TEST_ONE_PART_INF ((VAL1) / (_Complex double)1);

  RUNTIME_TESTIT (double, 1, /, VAL1, 0);
  STATICINIT_TESTIT (double, 1, /, VAL1, 0);

  return 0;
}
