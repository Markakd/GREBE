/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-vrp1" } */

int
f (int m1, int m2, int c)
{
  int d = m1 > m2;
  int e = d * c;
  return e ? m1 : m2;
}

/* { dg-final { scan-tree-dump-times "\\? c_\[0-9\]\\(D\\) : 0" 1 "vrp1" } } */
