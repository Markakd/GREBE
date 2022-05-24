/* { dg-do link } */
/* { dg-excess-errors "lto1, mkoffload and lto-wrapper fatal errors" { target offload_device_nonshared_as } } */

int var; /* { dg-error "variable 'var' has been referenced in offloaded code but hasn't been marked to be included in the offloaded code" "" { target offload_device_nonshared_as } } */

#pragma omp declare target
void  __attribute__((noinline, noclone))
foo (void)
{
  var++;
}
#pragma omp end declare target

int
main ()
{
#pragma omp target
  foo ();
}
