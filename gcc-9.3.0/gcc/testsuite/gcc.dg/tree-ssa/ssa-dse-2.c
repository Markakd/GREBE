/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-dse1" } */

int a, b, c;
int
foo ()
{
  int *p;
  if (c)
    p = &a;
  else
    p = &b;

  *p = 3;
  *p = 4;
  return *p;
}


/* We should eliminate the first assignment to *p, but not the second.  */
/* { dg-final { scan-tree-dump-times " = 3" 0 "dse1"} } */
/* { dg-final { scan-tree-dump-times " = 4" 1 "dse1"} } */

