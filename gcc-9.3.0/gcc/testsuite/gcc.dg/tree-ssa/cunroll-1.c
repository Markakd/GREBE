/* { dg-do compile } */
/* { dg-options "-O3 -fdump-tree-cunrolli-details" } */
int a[2];
void
test(int c)
{ 
  int i;
  for (i=0;i<c;i++)
    a[i]=5;
}
/* Array bounds says the loop will not roll much.  */
/* { dg-final { scan-tree-dump "loop with 2 iterations completely unrolled" "cunrolli"} } */
/* { dg-final { scan-tree-dump "Last iteration exit edge was proved true." "cunrolli"} } */
