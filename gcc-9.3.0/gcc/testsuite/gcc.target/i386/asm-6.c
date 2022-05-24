/* PR rtl-optimization/44174 */
/* Testcase by Jakub Jelinek <jakub@gcc.gnu.org> */

/* { dg-do compile { target fpic } } */
/* { dg-options "-O2 -fpic" } */

int f0 (int, int, int, int, int);
int f1 (void);

void
f2 (void)
{
  unsigned v1, v2, v3, v4;
  __asm__ ("" : "=a" (v1), "=d" (v2), "=c" (v3), "=r" (v4));
  f0 (f1 (), f1 (), f1 (), f1 (), (v4 >> 8) & 0xff);
}
