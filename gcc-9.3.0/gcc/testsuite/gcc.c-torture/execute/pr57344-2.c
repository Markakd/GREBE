/* PR middle-end/57344 */
/* { dg-require-effective-target int32plus } */

struct __attribute__((packed)) S
{
  int a : 27;
#if __SIZEOF_INT__ * __CHAR_BIT__ >= 32
  int b : 22;
#else
  int b : 13;
#endif
  char c;
  int : 0;
} s[2];
int i;

__attribute__((noinline, noclone)) void
foo (int x)
{
  if (x != -3161)
    __builtin_abort ();
  asm volatile ("" : : : "memory");
}

int
main ()
{
  struct S t = { 0, -3161L };
  s[1] = t;
  for (; i < 1; i++)
    foo (s[1].b);
  return 0;
}
