/* { dg-do run } */
/* { dg-require-effective-target xop } */
/* { dg-options "-O2 -mxop" } */

#include "xop-check.h"

#include <x86intrin.h>
#include <string.h>

#define NUM 10

union
{
  __m128i x[NUM];
  signed char ssi[NUM * 16];
  short si[NUM * 8];
  int li[NUM * 4];
  long long lli[NUM * 2];
} dst, res, src1;

static void
init_sbyte ()
{
  int i;
  for (i=0; i < NUM * 16; i++)
    src1.ssi[i] = i;
}

static void
init_sword ()
{
  int i;
  for (i=0; i < NUM * 8; i++)
    src1.si[i] = i;
}


static void
init_sdword ()
{
  int i;
  for (i=0; i < NUM * 4; i++)
    src1.li[i] = i;
}

static int 
check_sbyte2word ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < NUM * 16; i = i + 16)
    {
      for (j = 0; j < 8; j++)
	{
	  t = i + (2 * j);
	  s = (i / 2) + j;
	  res.si[s] = src1.ssi[t] + src1.ssi[t + 1] ;
	  if (res.si[s] != dst.si[s]) 
	    check_fails++;	
	}
    }
}

static int 
check_sbyte2dword ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < NUM * 16; i = i + 16)
    {
      for (j = 0; j < 4; j++)
	{
	  t = i + (4 * j);
	  s = (i / 4) + j;
	  res.li[s] = (src1.ssi[t] + src1.ssi[t + 1]) + (src1.ssi[t + 2]
	              + src1.ssi[t + 3]); 
	  if (res.li[s] != dst.li[s]) 
	    check_fails++;
	}
    }
  return check_fails++;
}

static int
check_sbyte2qword ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < NUM * 16; i = i + 16)
    {
      for (j = 0; j < 2; j++)
	{
	  t = i + (8 * j);
	  s = (i / 8) + j;
	  res.lli[s] = ((src1.ssi[t] + src1.ssi[t + 1]) + (src1.ssi[t + 2] 
		       + src1.ssi[t + 3])) + ((src1.ssi[t + 4] + src1.ssi[t +5])
	               + (src1.ssi[t + 6] + src1.ssi[t + 7])); 
	  if (res.lli[s] != dst.lli[s]) 
	    check_fails++;
	}
    }
  return check_fails++;
}

static int
check_sword2dword ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < (NUM * 8); i = i + 8)
    {
      for (j = 0; j < 4; j++)
	{
	  t = i + (2 * j);
	  s = (i / 2) + j;
	  res.li[s] = src1.si[t] + src1.si[t + 1] ;
	  if (res.li[s] != dst.li[s]) 
	    check_fails++;	
	}
    }
}

static int 
check_sword2qword ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < NUM * 8; i = i + 8)
    {
      for (j = 0; j < 2; j++)
	{
	  t = i + (4 * j);
	  s = (i / 4) + j;
	  res.lli[s] = (src1.si[t] + src1.si[t + 1]) + (src1.si[t + 2]
	               + src1.si[t + 3]); 
	  if (res.lli[s] != dst.lli[s]) 
	    check_fails++;
	}
    }
  return check_fails++;
}

static int
check_dword2qword ()
{
  int i, j, s, t, check_fails = 0;
  for (i = 0; i < (NUM * 4); i = i + 4)
    {
      for (j = 0; j < 2; j++)
	{
	  t = i + (2 * j);
	  s = (i / 2) + j;
	  res.lli[s] = src1.li[t] + src1.li[t + 1] ;
	  if (res.lli[s] != dst.lli[s]) 
	    check_fails++;	
	}
    }
}

static void
xop_test (void)
{
  int i;

  init_sbyte ();
  
  for (i = 0; i < NUM; i++)
    dst.x[i] = _mm_haddw_epi8 (src1.x[i]);
  
  if (check_sbyte2word())
  abort ();
  

  for (i = 0; i < (NUM ); i++)
    dst.x[i] = _mm_haddd_epi8 (src1.x[i]);
  
  if (check_sbyte2dword())
    abort (); 
  

  for (i = 0; i < NUM; i++)
    dst.x[i] = _mm_haddq_epi8 (src1.x[i]);
  
  if (check_sbyte2qword())
    abort ();


  init_sword ();

  for (i = 0; i < (NUM ); i++)
    dst.x[i] = _mm_haddd_epi16 (src1.x[i]);
  
  if (check_sword2dword())
    abort (); 

  for (i = 0; i < NUM; i++)
    dst.x[i] = _mm_haddq_epi16 (src1.x[i]);
  
  if (check_sword2qword())
    abort ();
 

  init_sdword ();

    for (i = 0; i < NUM; i++)
    dst.x[i] = _mm_haddq_epi32 (src1.x[i]);
  
  if (check_dword2qword())
    abort ();

}
