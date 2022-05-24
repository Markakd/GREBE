/* { dg-options "-fno-tree-scev-cprop -floop-nest-optimize -fgraphite-identity -O -fdump-tree-graphite-all" } */

void bar (void);

int toto()
{
  int i, j, k;
  int a[101][100];
  int b[100];

  for (i = 1; i < 100; i++)
    {
      for (j = 1; j < 100; j++)
	for (k = 1; k < 100; k++)
	  a[j][k] = a[j+1][i-1] + 2;

      b[i] = b[i-1] + 2;

      bar ();

      for (j = 1; j < 100; j++)
	a[j][i] = a[j+1][i-1] + 2;

      b[i] = b[i-1] + 2;

      bar ();

      for (j = 1; j < 100; j++)
	a[j][i] = a[j+1][i-1] + 2;

      b[i] = a[i-1][i] + 2;

      for (j = 1; j < 100; j++)
	a[j][i] = a[j+1][i-1] + 2;
    }

  return a[3][5] + b[1];
}

/* { dg-final { scan-tree-dump-times "number of SCoPs: 2" 1 "graphite"} } */
