/* { dg-do compile } */
/* { dg-options "-O3 -fno-ipa-sra -fdump-ipa-cp-details -fdump-tree-optimized-slim"  } */
/* { dg-add-options bind_pic_locally } */

struct S
{
  int a, b, c;
};

void *blah(int, void *);

static void __attribute__ ((noinline))
foo (int z, struct S *p)
{
  int i, c = p->c;
  int b = p->b;
  void *v = (void *) p;

  for (i= 0; i< c; i++)
    v = blah(b + i, v);
}

void
entry (int c)
{
  struct S s;
  int i;

  for (i = 0; i<c; i++)
    {
      s.a = 1;
      s.b = 64;
      s.c = 32;
      foo (i, &s);
    }
  s.c = 2;
  foo (0, &s);
}
/* { dg-final { scan-ipa-dump-times "Creating a specialized node of foo/\[0-9\]*\\." 2 "cp" } } */
/* { dg-final { scan-ipa-dump-times "Aggregate replacements: 1" 2 "cp" } } */
/* { dg-final { scan-ipa-dump-times "Aggregate replacements: 0" 2 "cp" } } */
/* { dg-final { scan-tree-dump-not "->c;" "optimized" } } */
