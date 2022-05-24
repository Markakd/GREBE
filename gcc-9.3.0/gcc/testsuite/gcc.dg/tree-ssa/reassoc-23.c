/* { dg-do compile } */ 
/* { dg-options "-O2 -fdump-tree-reassoc1" } */

unsigned int
foo(unsigned int a, unsigned int b, unsigned int c, unsigned int d,
    unsigned int e, unsigned int f, unsigned int g, unsigned int h)
{
  /* Should be transformed into e = 20 */
  unsigned int i = (a + 9);
  unsigned int j = (-c + 1);
  i += (c + 8);
  j += (-a + 2);
  e = i + j;
  return e;
}

/* { dg-final { scan-tree-dump-times "= 20" 1 "reassoc1"} } */
