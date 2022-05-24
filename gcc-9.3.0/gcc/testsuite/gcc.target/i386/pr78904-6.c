/* PR target/78904 */
/* { dg-do compile } */
/* { dg-require-effective-target nonpic } */
/* { dg-options "-O2 -masm=att" } */

typedef __SIZE_TYPE__ size_t;

struct S1
{
  char pad1;
  char val;
  short pad2;
};

extern char t[256];

void foo (struct S1 a, size_t i)
{
  t[i] = a.val;
}

/* { dg-final { scan-assembler "\[ \t\]movb\[\t \]*%.h, t" } } */
