/* { dg-do run { target { powerpc*-*-* && { p8vector_hw && int128 } } } } */
/* { dg-options "-mdejagnu-cpu=power8 -O3" } */

/* Test that the vec_addec builtin works as expected.  */

#include "altivec.h"

#define N 4096

void abort ();

#define define_test_functions(STYPE, NAMESUFFIX) \
\
STYPE result_##NAMESUFFIX[N]; \
STYPE addend1_##NAMESUFFIX[N]; \
STYPE addend2_##NAMESUFFIX[N]; \
STYPE carry_##NAMESUFFIX[N]; \
STYPE expected_##NAMESUFFIX[N]; \
\
__attribute__((noinline)) void vector_tests_##NAMESUFFIX () \
{ \
  vector STYPE v1, v2, v3, tmp; \
  int i; \
  for (i = 0; i < N; i+=16/sizeof (STYPE)) \
    { \
      /* result=carry of addend1+addend2+(carry & 0x1).  */ \
      v1 = (vector STYPE) { addend1_##NAMESUFFIX[i] }; \
      v2 = (vector STYPE) { addend2_##NAMESUFFIX[i] }; \
      v3 = (vector STYPE) { carry_##NAMESUFFIX[i] }; \
\
      tmp = vec_addec (v1, v2, v3); \
      result_##NAMESUFFIX[i] = tmp[0]; \
    } \
} \
\
__attribute__((noinline)) void init_##NAMESUFFIX () \
{ \
  int i; \
  for (i = 0; i < N; ++i) \
    { \
      result_##NAMESUFFIX[i] = 0; \
      if (i%6 == 0) \
	{ \
	  addend1_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64); \
	  addend2_##NAMESUFFIX[i] =  0xfffffffffffffffe; \
	  carry_##NAMESUFFIX[i] = 1; \
	  expected_##NAMESUFFIX[i] = 0; \
	} \
      else if (i%6 == 1) \
	{ \
	  addend1_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64) + \
				    0xffffffffffffffff; \
	  addend2_##NAMESUFFIX[i] = 1; \
	  carry_##NAMESUFFIX[i] = 0; \
	  expected_##NAMESUFFIX[i] = 1; \
	} \
      else if (i%6 == 2) \
	{ \
	  addend1_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64) + \
				    0xffffffffffffffff; \
	  addend2_##NAMESUFFIX[i] = 0; \
	  carry_##NAMESUFFIX[i] = 3; /* 3 should work like 1 here.  */ \
	  expected_##NAMESUFFIX[i] = 1; \
	}  \
      else if (i%6 == 3) \
	{ \
	  addend1_##NAMESUFFIX[i] = 1; \
	  addend2_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64) + \
				    0xffffffffffffffff; \
	  carry_##NAMESUFFIX[i] = 2; /* 2 should work like 0 here.  */ \
	  expected_##NAMESUFFIX[i] = 1; \
	} \
      else if (i%6 == 4) \
	{ \
	  addend1_##NAMESUFFIX[i] = 0; \
	  addend2_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64) + \
				    0xffffffffffffffff; \
	  carry_##NAMESUFFIX[i] = 1; \
	  expected_##NAMESUFFIX[i] = 1; \
	} \
      else if (i%6 == 5) \
	{ \
	  addend1_##NAMESUFFIX[i] = ((__int128)0xffffffffffffffff << 64); \
	  addend2_##NAMESUFFIX[i] = 0xffffffffffffffff; \
	  carry_##NAMESUFFIX[i] = 1; \
	  expected_##NAMESUFFIX[i] = 1; \
	} \
    } \
} \
\
__attribute__((noinline)) void verify_results_##NAMESUFFIX () \
{ \
  int i; \
  for (i = 0; i < N; ++i) \
    { \
      if (result_##NAMESUFFIX[i] != expected_##NAMESUFFIX[i]) \
	abort (); \
    } \
}


#define execute_test_functions(STYPE, NAMESUFFIX) \
{ \
  init_##NAMESUFFIX (); \
  vector_tests_##NAMESUFFIX (); \
  verify_results_##NAMESUFFIX (); \
}


define_test_functions (signed __int128, si128);
define_test_functions (unsigned __int128, ui128);

int main ()
{
  execute_test_functions (signed __int128, si128);
  execute_test_functions (unsigned __int128, ui128);

  return 0;
}


