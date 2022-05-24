/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-alias-vops" } */

struct {
	int i;
	int x[128];
	int j;
} a;

int foo(int i)
{
	a.x[i] = 0;
	return a.x[i];
}

/* { dg-final { scan-tree-dump "VDEF" "alias" } } */

