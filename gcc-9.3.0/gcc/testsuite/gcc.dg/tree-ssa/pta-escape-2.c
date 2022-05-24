/* { dg-do run } */
/* { dg-options "-O -fdump-tree-alias-details -fdelete-null-pointer-checks" } */

int *i;
void __attribute__((noinline))
foo (void)
{
  *i = 1;
}
int __attribute__((noinline))
bar(int local_p, int **q)
{
  int x = 0;
  int *j;
  int **p;
  if (local_p)
    p = &j;
  else
    p = q;
  *p = &x;  /* This makes x escape.  */
  foo ();
  return x;
}
extern void abort (void);
int main()
{
  int k = 2;
  int **q = &i;
  i = &k;
  if (bar (1, q) != 0 || k != 1)
    abort ();
  if (bar (0, q) != 1)
    abort ();
  return 0;
}

/* { dg-final { scan-tree-dump "ESCAPED = { NULL ESCAPED NONLOCAL x }" "alias" { target { ! keeps_null_pointer_checks } } } } */
/* { dg-final { scan-tree-dump "ESCAPED = { ESCAPED NONLOCAL x }" "alias" { target { keeps_null_pointer_checks } } } } */
