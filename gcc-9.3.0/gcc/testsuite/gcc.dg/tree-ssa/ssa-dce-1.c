/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-dce3" } */

int t() __attribute__ ((const));
void
q()
{
  int i = t();
  if (!i)
    i = t();
}
/* There should be no IF conditionals.  */
/* { dg-final { scan-tree-dump-times "if " 0 "dce3"} } */
