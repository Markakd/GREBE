/* { dg-do compile } */
/* { dg-options "-fstrict-overflow -fdump-tree-gimple" } */
int g(int x)
{
   return (x + 10) < 0;
}
/* There should be only x < -10 and no x + 10. */
/* { dg-final { scan-tree-dump-times "< -10" 1 "gimple"} } */
/* { dg-final { scan-tree-dump-times "\\+ 10" 0 "gimple"} } */
