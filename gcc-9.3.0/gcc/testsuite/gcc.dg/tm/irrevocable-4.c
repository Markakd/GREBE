/* { dg-do compile } */
/* { dg-options "-fgnu-tm -fdump-tree-tmmark" } */

void orig(void);
void xyz(void) __attribute__((transaction_wrap (orig)));

void
foo()
{
	__transaction_relaxed {
		orig();
	}
}

/* { dg-final { scan-tree-dump-times "hasNoIrrevocable" 0 "tmmark" } } */
