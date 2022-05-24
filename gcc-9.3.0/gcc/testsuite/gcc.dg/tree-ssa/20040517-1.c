/* { dg-do compile } */
/* { dg-options "-O1 -fdump-tree-alias-vops" } */
extern void abort (void);
int a; 
 
extern void __attribute__ ((malloc)) *foo ();
 
void bar (void) 
{ 
  a = 1; 
  foo (); 
  if (a) 
    abort (); 
} 

/* We used to treat malloc functions like pure and const functions, but
   malloc functions may clobber global memory.  Only the function result
   does not alias any other pointer.
   Hence, we must have a VDEF for a before and after the call to foo().
   And one after the call to abort().  */
/* { dg-final { scan-tree-dump-times "VDEF" 3 "alias"} } */
