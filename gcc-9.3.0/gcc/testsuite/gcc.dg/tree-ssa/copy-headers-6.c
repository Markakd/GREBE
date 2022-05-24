/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-ch2-details" } */

int is_sorted(int *a, int n)
{
  for (int i = 0; i < n - 1; i++)
    if (a[i] > 0)
      return 0;
  return 1;
}

/* Verify we apply loop header copying but only copy the IV test and
   not the alternate exit test.  */

/* { dg-final { scan-tree-dump "is now do-while loop" "ch2" } } */
/* { dg-final { scan-tree-dump-times "  if " 3 "ch2" } } */
