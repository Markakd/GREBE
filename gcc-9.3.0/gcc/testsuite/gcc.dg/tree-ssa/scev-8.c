/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-ivopts-details" } */

int *a;

int
foo1 (long long s, long long l)
{
  long long i;

  for (i = s; i < l; i++)
    {
      a[(short)i] = 0;
    }
  return 0;
}

int
foo2 (unsigned char s, unsigned char l, unsigned char c)
{
  unsigned char i, step = 1;
  int sum = 0;

  for (i = s; i < l; i++)
    {
      sum += a[c];
      c += step;
    }

  return sum;
}

int
foo3 (unsigned char s, unsigned char l, unsigned char c)
{
  unsigned char i;
  int sum = 0;

  for (i = s; i != l; i += c)
    {
      sum += a[i];
    }

  return sum;
}

int
foo4 (unsigned char s, unsigned char l)
{
  unsigned char i;
  int sum = 0;

  for (i = s; i != l; i++)
    {
      sum += a[i];
    }

  return sum;
}

/* Address of array references are not scevs.  */
/* { dg-final { scan-tree-dump-not "  Type:\\tADDRESS\n  Use \[0-9\].\[0-9\]:" "ivopts" } } */
