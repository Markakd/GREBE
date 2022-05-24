/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-cddce1" } */

int main(void)
{
  unsigned i, j;

  for (i = 1, j = 0; i != 0; i+=2)
    {
      j += 500;
      if (j % 7)
	{
	  j++;
	}
      else
	{
	  j--;
	}
    }

  return 0;
}

/* We now can prove the infiniteness of the loop during CCP and fail
   to eliminate the code inside the infinite loop because we start
   by marking the j % 7 condition as useful.  See PR45178.  */

/* We should eliminate the inner condition, but the loop must be preserved
   as it is infinite.  Therefore there should be just one goto and no PHI.  */
/* { dg-final { scan-tree-dump-times "PHI " 0 "cddce1" } } */
/* { dg-final { scan-tree-dump-times "goto" 1 "cddce1" } } */
