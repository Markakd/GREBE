/* { dg-require-stack-check "generic" } */
/* { dg-options "-O -fstack-check=generic -ftree-pre -fgraphite-identity" } */
/* nvptx doesn't expose a stack.  */
/* { dg-skip-if "" { nvptx-*-* } } */

int main ()
{
  int i, j;
  int x[8][8];
  for (i = 0; i < 8; i++)
    for (j = i; j < 8; j++)
      x[i][j] = 4;

  for (i = 0; i < 8; i++)
    for (j = i; j < 8; j++)
      if (x[i][j] != 4)
	__builtin_abort ();

  return 0;
}
