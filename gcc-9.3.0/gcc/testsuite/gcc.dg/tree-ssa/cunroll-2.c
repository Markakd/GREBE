/* { dg-do compile } */
/* { dg-options "-O3 -fdump-tree-cunroll-details" } */
int a[2];
int test2 (void);
void
test(int c)
{ 
  int i;
  for (i=0;i<c;i++)
    {
      a[i]=5;
      if (test2())
	return;
    }
}
/* We are not able to get rid of the final conditional because the loop has two exits.  */
/* { dg-final { scan-tree-dump "loop with 1 iterations completely unrolled" "cunroll"} } */
