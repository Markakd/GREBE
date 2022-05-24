/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-optimized -w" } */
/* { dg-options "-O1 -fdump-tree-optimized -w -msse" { target { i?86-*-* x86_64-*-* } } } */
/* Check that SRA replaces structures containing vectors. */

#define vector __attribute__((vector_size(16)))

struct vt
{
  vector int t;
};


vector int f(vector int t1, vector int t2)
{
  struct vt st1, st2, st3;
  st1.t = t1;
  st2 = st1;
  st2.t += t2;
  st3 = st2;
  return st3.t;
}

/* { dg-final { scan-tree-dump-times "st" 0 "optimized" } } */
