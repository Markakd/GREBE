/* { dg-do compile { target *-*-solaris2.* } } */
/* { dg-options "-Wformat" } */

#include "format.h"

void cmn_err_func (int level, char * format, ...)
  __attribute__((format (cmn_err, 2, 3)));

void cmn_err_func (int level, char * format, ...)
{
}

const char *string = "foo";

int main()
{
  int i = 1;
  long l = 2;
  llong ll = 3;

  cmn_err_func (0, "%s", string);
  cmn_err_func (0, "%d %D %o %O %x %X %u", i, i, i, i, i, i, i);
  cmn_err_func (0, "%ld %lD %lo %lO %lx %lX %lu", l, l, l, l, l, l, l);
  cmn_err_func (0, "%lld %llD %llo %llO %llx %llX %llu",
		ll, ll, ll, ll, ll, ll, ll);
  cmn_err_func (0, "%b %s", i, "\01Foo", string);
  cmn_err_func (0, "%p", string);
  cmn_err_func (0, "%16b", i, "\01Foo");

  cmn_err_func (0, "%i", i);		/* { dg-warning "unknown|too many" } */
  cmn_err_func (0, "%d", l);		/* { dg-warning "expects argument" } */
  cmn_err_func (0, "%b");		/* { dg-warning "'int'" } */
/* { dg-warning "'char \\*'" "" { target *-*-solaris2.* } .-1 } */
  cmn_err_func (0, "%b", i);		/* { dg-warning "matching" } */
  cmn_err_func (0, "%b", i, i);		/* { dg-warning "expects argument" } */
  cmn_err_func (0, "%b", string, i);	/* { dg-warning "expects argument" } */
  cmn_err_func (0, "%p", 3);		/* { dg-warning "expects argument" } */
  return 0;
}
