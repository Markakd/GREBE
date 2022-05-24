// PR 20647, we must emit the typeinfo's string as weak, but not the
// necessarily the type info object

// { dg-require-weak "" }
// { dg-skip-if "Linkonce not weak" { *-*-mingw* *-*-cygwin } }
// { dg-final { scan-assembler ".weak\[ \t\]_?_ZTSPP1A" { target { ! { *-*-darwin* hppa*-*-hpux* } } } } }
// { dg-final { scan-assembler-not ".weak\[ \t\]_?_ZTIPP1A" { target { ! { *-*-darwin* } } } } }
// { dg-final { scan-assembler ".weak_definition\[ \t\]_?_ZTSPP1A" { target { *-*-darwin* } } } }
// { dg-final { scan-assembler-not ".weak_definition\[ \t\]_?_ZTIPP1A" { target { *-*-darwin* } } } }

struct A;

void Foo ()
{
  throw (A **)0;
}
