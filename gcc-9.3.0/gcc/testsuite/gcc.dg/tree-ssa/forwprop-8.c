/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-forwprop1 -W -Wall" } */


struct X { int a[5]; };
int foo(struct X *q)
{
  int (*pointer)[5] = &q->a;
  return (*pointer)[0];
}


/* We should have propragated &q->a into (*pointer).  */
/* { dg-final { scan-tree-dump "q_.\\\(D\\\)\\\]\\\[0\\\];" "forwprop1" } } */
