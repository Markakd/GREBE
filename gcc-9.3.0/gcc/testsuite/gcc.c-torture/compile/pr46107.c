/* PR tree-optimization/46107 */
/* { dg-require-effective-target indirect_jumps } */
/* { dg-require-effective-target label_values } */

int foo (void) __attribute__ ((noreturn));

void
bar (int x, int *y, int z)
{
  static void *j[] = { &&l1, &&l2 };
l1:
  if (*y)
    goto *j[z];
  foo ();
l2:
  *y ^= (x & 1) ? -1 : 0;
  goto *j[x];
}
