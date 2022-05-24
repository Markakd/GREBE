/* Origin: PR target/11693 from Andreas Schwab <schwab@suse.de> */
/* { dg-do compile } */
/* { dg-options "-O2 -frename-registers" } */

static inline unsigned long long
foo (void)
{
  unsigned long long x;
  __asm__ __volatile__ ("" : "=r" (x) :: "memory");
  return x;
}

static inline void
bar (unsigned long long x, unsigned long long y)
{
  __asm__ __volatile__ ("" :: "r"(x), "r"(y) : "memory");
}

static inline void
baz (unsigned long long x, unsigned long long y, unsigned long long z,
     unsigned long long p, unsigned long long q)
{
  __asm__ __volatile__ ("" :: "r" (q << 2) : "memory");
  __asm__ __volatile__ ("" :: "r" (z) : "memory");
  if (x & 0x1)
    __asm__ __volatile__ ("" :: "r" (y), "r" (p) : "memory");
  if (x & 0x2)
    __asm__ __volatile__ ("" :: "r" (y), "r" (p) : "memory");
}

static inline unsigned long long
ffz (unsigned long long x)
{
  unsigned long long r;
  __asm__ ("" : "=r" (r) : "r" (x & (~x - 1)));
  return r;
}

void die (const char *, ...) __attribute__ ((noreturn));

void
test (void *x)
{
  unsigned long long a, c;

  a = foo ();
  bar (0xc000000000000000LL, 0x660);
  bar (0xa00000000000c000LL, 0x539);
  baz (2, 1, 0xa000000000008000LL,
       ({ unsigned long long b;
	  b = ({ unsigned long long d; __asm__ ("" : "=r" (d) : "r" (x)); d; })
	      + 0x10000000000661LL;
	  b;
	}),
       14);
  c = ffz (0x1fffffffffffffffLL);
  if (c < 51 || c > 61)
    die ("die", c - 1);
}
