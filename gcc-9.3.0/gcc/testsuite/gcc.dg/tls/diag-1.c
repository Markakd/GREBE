/* Valid __thread specifiers.  */
/* { dg-require-effective-target tls } */

__thread int g1;
extern __thread int g2;
static __thread int g3;

void foo()
{
  extern __thread int l1;
  static __thread int l2;
}
