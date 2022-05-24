/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-lim2-details" } */

int x;
int a[100];

struct a
{
  int X;
  int Y;
};

/* Word size is long long for 64-bit mingw target.  */
#ifdef _WIN64
#define LONG long long
#else
#define LONG long
#endif

struct a arr[100];

void test1(int b)
{
  unsigned i;

  /* And here.  */
  for (i = 0; i < 100; i++)
    {
      arr[b+8].X += i;
      arr[b+9].X += i;
    }
}

void test2(struct a *A, int b)
{
  unsigned i;

  /* And here as well.  */
  for (i = 0; i < 100; i++)
    {
      A[b].X += i;
      A[b+1].Y += i;
    }
}

void test3(unsigned LONG b)
{
  unsigned i;

  /* And here.  */
  for (i = 0; i < 100; i++)
    {
      arr[b+8].X += i;
      arr[b+9].X += i;
    }
}

void test4(struct a *A, unsigned LONG b)
{
  unsigned i;

  /* And here as well.  */
  for (i = 0; i < 100; i++)
    {
      A[b].X += i;
      A[b+1].Y += i;
    }
}
/* long index not hoisted for avr target PR 36561 */
/* { dg-final { scan-tree-dump-times "Executing store motion of" 8 "lim2" { xfail { avr-*-* msp430-*-* } } } } */
/* { dg-final { scan-tree-dump-times "Executing store motion of" 6 "lim2" { target { avr-*-* msp430-*-* } } } } */
