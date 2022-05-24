/* { dg-do run } */
/* { dg-options "-O2 -msse" } */
/* { dg-require-effective-target sse } */

#include "sse-check.h"

#include <xmmintrin.h>
#include <string.h>

#define SHIFT (4)

typedef union {
  __m64 v;
  unsigned char c[8];
  unsigned short int s[4];
  unsigned long long t;
  unsigned int u[2];
}vecInWord;

void sse_tests (void) __attribute__((noinline));
void dump64_16 (char *, char *, vecInWord);
int check (const char *, const char *[]);

char buf[8000];
char comparison[8000];
static int errors = 0;

vecInWord c64, e64;
__m64 m64_64;

const char *reference_sse[] = {
  "_mm_shuffle_pi16 0123 4567 89ab cdef \n",
  ""
};

static void
sse_test (void)
{
  e64.t  = 0x0123456789abcdefULL;

  m64_64 = e64.v;

  sse_tests();
  check (buf, reference_sse);
#ifdef DEBUG
  printf ("sse testing:\n");
  printf (buf);
  printf ("\ncomparison:\n");
  printf (comparison);
#endif
  buf[0] = '\0';

  if (errors != 0)
    abort ();
}

void __attribute__((noinline))
sse_tests (void)
{
  /* pshufw */
  c64.v = _mm_shuffle_pi16 (m64_64, 0x1b);
  dump64_16 (buf, "_mm_shuffle_pi16", c64);
}

void
dump64_16 (char *buf, char *name, vecInWord x)
{
  int i;
  char *p = buf + strlen (buf);

  sprintf (p, "%s ", name);
  p += strlen (p);

  for (i=0; i<4; i++)
    {
      sprintf (p, "%4.4x ", x.s[i]);
      p += strlen (p);
    }
  strcat (p, "\n");
}

int
check (const char *input, const char *reference[])
{
  int broken, i, j, len;
  const char *p_input;
  char *p_comparison;
  int new_errors = 0;

  p_comparison = &comparison[0];
  p_input = input;

  for (i = 0; *reference[i] != '\0'; i++)
    {
      broken = 0;
      len = strlen (reference[i]);
      for (j = 0; j < len; j++)
	{
	  /* Ignore the terminating NUL characters at the end of every string in 'reference[]'.  */
	  if (!broken && *p_input != reference[i][j])
	    {
	      *p_comparison = '\0';
	      strcat (p_comparison, " >>> ");
	      p_comparison += strlen (p_comparison);
	      new_errors++;
	      broken = 1;
	    }
	  *p_comparison = *p_input;
	  p_comparison++;
	  p_input++;
	}
      if (broken)
	{
	  *p_comparison = '\0';
	  strcat (p_comparison, "expected:\n");
	  strcat (p_comparison, reference[i]);
	  p_comparison += strlen (p_comparison);
	}
    }
  *p_comparison = '\0';
  strcat (p_comparison, new_errors ? "failure\n\n" : "O.K.\n\n") ;
  errors += new_errors;
  return 0;
}
