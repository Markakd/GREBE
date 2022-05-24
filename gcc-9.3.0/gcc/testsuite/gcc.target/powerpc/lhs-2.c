/* { dg-do compile { target { powerpc*-*-* } } } */
/* { dg-skip-if "" { powerpc*-*-darwin* } } */
/* { dg-options "-O2 -mdejagnu-cpu=power6 -msched-groups" } */
/* { dg-final { scan-assembler "ori 1,1,0" } } */

/* Test generation of group ending nop in load hit store situation.  */
typedef union {
  double val;
  struct {
    unsigned int w1;
    unsigned int w2;
  };
} words;

unsigned int f (double d)
{
  words u;
  u.val = d;
  return u.w2;
}

