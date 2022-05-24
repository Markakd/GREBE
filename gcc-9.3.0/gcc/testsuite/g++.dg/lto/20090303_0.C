/* { dg-lto-do run } */
/* { dg-require-effective-target fpic } */
/* { dg-lto-options {{-flto -flto-partition=1to1 -fPIC}} } */
/* { dg-lto-options {{-flto -flto-partition=1to1}} { target sparc*-*-* } } */
/* { dg-suppress-ld-options {-fPIC} }  */
void foobar(int *, int* __x)    ;
int test_ints[30];
int j;

void foobar (int *x, int *y)
{
  *x = *y = 0;
}

void Test() {
 int int_set_;
 foobar (&int_set_, &test_ints[j]);
}

int
main()
{
  Test();
  return 0;
}

