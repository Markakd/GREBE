/* { dg-do compile } */

/* N1150 3: Decimal floating types.
   C99 6.4.1(2): Keywords.
   Decimal float keywords cannot be used in other contexts.  */

int _Decimal32 (void)		/* { dg-error "" } */
{
  return 0;
}

int foo (int i)
{
  int _Decimal64 = i * 2;	/* { dg-error "" } */
  return _Decimal64;		/* { dg-error "" } */
}
