/* { dg-do run { target { ilp32 || lp64 } } } */
/* { dg-skip-if "" { *-*-* }  { "*" } { "-O2 -Wno-address-of-packed-member" } } */
/* { dg-additional-options "-fno-omit-frame-pointer" { target *-*-darwin* } } */
/* { dg-shouldfail "asan" } */

struct S { int i; } __attribute__ ((packed));

__attribute__((noinline, noclone)) int
foo (struct S *s)
{
  return s->i;
}

__attribute__((noinline, noclone)) int
bar (int *s)
{
  return *s;
}

__attribute__((noinline, noclone)) struct S
baz (struct S *s)
{
  return *s;
}

int
main ()
{
  struct T { char a[3]; struct S b[3]; char c; } t;
  int v = 5;
  struct S *p = t.b;
  asm volatile ("" : "+rm" (p));
  p += 3;
  if (bar (&v) != 5) __builtin_abort ();
  volatile int w = foo (p);
  return 0;
}

/* { dg-output "ERROR: AddressSanitizer:\[^\n\r]*on address\[^\n\r]*" } */
/* { dg-output "0x\[0-9a-f\]+ at pc 0x\[0-9a-f\]+ bp 0x\[0-9a-f\]+ sp 0x\[0-9a-f\]+\[^\n\r]*(\n|\r\n|\r)" } */
/* { dg-output "\[^\n\r]*READ of size 4 at 0x\[0-9a-f\]+ thread T0\[^\n\r]*(\n|\r\n|\r)" } */
/* { dg-output "    #0 0x\[0-9a-f\]+ +(in _*foo(\[^\n\r]*misalign-1.c:1\[01]|\[^\n\r]*:0|\[^\n\r]*\\+0x\[0-9a-z\]*)|\[(\])\[^\n\r]*(\n|\r\n|\r)" } */
/* { dg-output "    #1 0x\[0-9a-f\]+ +(in _*main (\[^\n\r]*misalign-1.c:3\[45]|\[^\n\r]*:0|\[^\n\r]*\\+0x\[0-9a-z\]*)|\[(\]).*(\n|\r\n|\r)" } */
