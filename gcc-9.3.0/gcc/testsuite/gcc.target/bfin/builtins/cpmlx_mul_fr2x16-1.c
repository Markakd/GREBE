extern void abort (void);

typedef short  __v2hi __attribute ((vector_size(4)));
typedef __v2hi fract2x16;
typedef short  fract16;

int main ()
{
  fract2x16 a, b, t;
  fract16 t1, t2;

  a = __builtin_bfin_compose_2x16 (0x2000, 0x1000);
  b = __builtin_bfin_compose_2x16 (0x2000, 0x1000);

  t = __builtin_bfin_cmplx_mul (a, b);
  t1 = __builtin_bfin_extract_hi (t);
  t2 = __builtin_bfin_extract_lo (t);
  if (t1 != 0x800 || t2 != 0xfffffa00)
    abort ();
  return 0;
}

