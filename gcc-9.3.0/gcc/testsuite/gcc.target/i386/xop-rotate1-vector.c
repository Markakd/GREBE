/* Test that the compiler properly optimizes vector rotate instructions vector
   into prot on XOP systems.  */

/* { dg-do compile { target { ! ia32 } } } */
/* { dg-options "-O2 -mxop -mno-avx2 -ftree-vectorize" } */

extern void exit (int);

typedef long __m128i  __attribute__ ((__vector_size__ (16), __may_alias__));

#define SIZE 10240

union {
  __m128i i_align;
  unsigned u32[SIZE];
} a, b, c;

void
left_rotate32 (void)
{
  int i;

  for (i = 0; i < SIZE; i++)
    a.u32[i] = (b.u32[i] << ((sizeof (int) * 8) - 4)) | (b.u32[i] >> 4);
}

int
main ()
{
  left_rotate32 ();
  exit (0);
}

/* { dg-final { scan-assembler "vprotd" } } */
