/* { dg-do compile } */
/* { dg-options "-O2 -fsplit-paths -fdump-tree-split-paths-details -w" } */

powi_cost (long n)
{
  unsigned char cache[256];
  unsigned long digit;
  unsigned long val;
  int result;
  while (val >= 256)
    {
      if (val & 1)
	{
	  result += powi_lookup_cost (digit, cache) + 3 + 1;
	}
      else
	{
	  val >>= 1;
	}
    }
}

/* { dg-final { scan-tree-dump-times "Duplicating join block" 1 "split-paths" } } */

