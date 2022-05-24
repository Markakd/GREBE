/* { dg-do run } */
/* { dg-options "-march=amdfam10 -mfma4 -mno-sse4a" } */

extern void abort (void);

int
main ()
{
#if !defined __SSE__
  abort ();
#endif
#if !defined __SSE2__
  abort ();
#endif
#if !defined __SSE3__
  abort ();
#endif
#if !defined __SSSE3__
  abort ();
#endif
#if !defined __SSE4_1__
  abort ();
#endif
#if !defined __SSE4_2__
  abort ();
#endif
#if defined __SSE4A__
  abort ();
#endif
#if defined __FMA4__
  abort ();
#endif
  return 0;
}
