#define N 10000
void foo (int);
int test ()
{
  int a[N + 8];
  unsigned i;

  for (i = 0; i < N; i++)
    {
      a[i] = i + 12;

      if (i == 40)
	a[i] = i;
      else
	a[i] = i+1;


      a[i] = i + 12;
      a[i] = a[i+1];
      a[i] += a[i+2];
      a[i] += a[i+3];
      a[i] += a[i+4];
      a[i] += a[i+5];
      a[i] += a[i+6];

    }

  return a[20];
}
