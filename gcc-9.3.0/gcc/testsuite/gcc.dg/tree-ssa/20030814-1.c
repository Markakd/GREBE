/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-dom2" } */
   
extern void abort (void);
extern void oof (int);

int
com(int *blah)
{
  int z = *blah;
  if (z == 256)
    {
      oof (z);
      abort ();
    }
  return *blah;
}

/* There should be precisely one load of blah.  If there is
   more than one, then the dominator optimizations failed.  */
/* { dg-final { scan-tree-dump-times "\\*blah" 1 "dom2"} } */
  
