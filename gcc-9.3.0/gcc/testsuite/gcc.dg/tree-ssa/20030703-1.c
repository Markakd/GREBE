/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-dom2" } */
  
extern void abort (void);
extern int blah[];

void
foo(int index)
{
  if (blah [(unsigned int)index] != 0)
    abort ();
  if (blah [(unsigned int)index] != 0)
    abort ();
}

/* There should be precisely one load of blah.  If there is
   more than one, then the dominator optimizations failed.  */
/* { dg-final { scan-tree-dump-times "blah" 1 "dom2"} } */
 
/* There should be exactly one IF conditional.  */
/* { dg-final { scan-tree-dump-times "if " 1 "dom2"} } */

