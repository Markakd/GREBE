/* { dg-do compile } */ 
/* { dg-options "-O2 -w -fdump-tree-dom2-details" } */

typedef struct rtx_def *rtx;
struct rtx_def
{
  int code;
  rtx rt_rtx;
};
rtx
try_combine (rtx i1, rtx newpat)
{
  rtx temp;
  if (i1 && (temp = ((((((newpat->rt_rtx, ((((temp)->code) == 42)))))))))
      && ((temp =
	(((((((((((newpat)->rt_rtx),
		 ((((temp)->code) == 42) && arf ())))))))))))))
    ;
  else if (i1 && foo ());
}

/* There should be four tests against i1.  One from the hash table
   dumps, one from the EVRP analyzer one from EVRP evaluation and one
   in the code itself.  */
/* { dg-final { scan-tree-dump-times "if .i1_" 4 "dom2"} } */

/* There should be no actual jump threads realized by DOM.  The
   legitimize jump threads are handled in VRP and those discovered
   by DOM are subsumed by collapsing a conditional.  */
/* { dg-final { scan-tree-dump-not "Threaded" "dom2"} } */
