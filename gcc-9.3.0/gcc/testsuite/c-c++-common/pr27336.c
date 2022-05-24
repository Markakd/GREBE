/* { dg-do compile } */
/* { dg-options "-O2 -fdelete-null-pointer-checks -fdump-tree-vrp1" } */
/* { dg-skip-if "" { keeps_null_pointer_checks } } */

struct B { int x; };
extern void g3(struct B *that)  __attribute__((nonnull));
int f3(struct B *a)
{
  g3(a);
  return a != (void *)0;
}

/* { dg-final { scan-tree-dump "return 1;" "vrp1" } } */
