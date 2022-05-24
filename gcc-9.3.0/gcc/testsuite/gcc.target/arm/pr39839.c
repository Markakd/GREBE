/* { dg-require-effective-target fpic } */
/* { dg-options "-Os -fpic" }  */
/* { dg-final { scan-assembler-not "str\[\\t \]*r.,\[\\t \]*.sp," } } */

struct S
{
  int count;
  char *addr;
};

void func(const char*, const char*, int, const char*);

/* This function should not need to spill to the stack. */
void test(struct S *p)
{
  int off = p->count;
  while (p->count >= 0)
    {
      const char *s = "xyz";
      if (*p->addr) s = "pqr";
      func("abcde", p->addr + off, off, s);
      p->count--;
    }
}
