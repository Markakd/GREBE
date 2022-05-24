// { dg-do compile { target c++11 } }
// { dg-require-effective-target tls }

// The reference temp should be TLS, not normal data.
// { dg-final { scan-assembler-not "\\.data" { target tls_native xfail powerpc-*-aix* } } }

thread_local int&& ir = 42;

void f()
{
  ir = 24;
}
