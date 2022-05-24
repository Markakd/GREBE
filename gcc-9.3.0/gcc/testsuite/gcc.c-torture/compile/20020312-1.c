/* { dg-do assemble } */
/* { dg-skip-if "" { pdp11-*-* } { "-O0" } { "" } } */

/* PR optimization/5892 */
typedef struct { unsigned long a; unsigned int b, c; } A;
typedef struct { unsigned long a; A *b; int c; } B;

static inline unsigned int
bar (unsigned int x)
{
  unsigned long r;
  asm ("" : "=r" (r) : "0" (x));
  return r >> 31;
}

int foo (B *x)
{
  A *y;
  y = x->b;
  y->b = bar (x->c);
  y->c = ({ unsigned int z = 1; (z << 24) | (z >> 24); });
}
