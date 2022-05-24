// Contributed by Dodji Seketeli <dodji@redhat.com>
// Origin PR debug/41170
// { dg-options "-gdwarf-2 -dA -fno-merge-debug-strings -gno-strict-dwarf" }
//
// We want to test that there is a DW_TAG_namespace DIE DW_AT_name is set
// to "not_emitted". That namespace die has a child DW_TAG_typedef DIE
// which DW_AT_name is the null terminated string "T".
// { dg-final { scan-assembler-times "DIE +\\(\[^\n\]*\\) DW_TAG_namespace" 1 } }
// { dg-final { scan-assembler-times "\"not_emitted.0\"\[^\n\]*DW_AT_name" 1 } }
// { dg-final { scan-assembler-times "DIE +\\(\[^\n\]*\\) DW_TAG_typedef" 1 } }
// { dg-final { scan-assembler-times "\.ascii \"T.0\"\[\t \]+\[^\n\]*DW_AT_name" 1 { xfail { powerpc-ibm-aix* } } } }

struct strukt
{
  int m;
};

namespace not_emitted
{
  typedef strukt T;
}

int
main()
{
  not_emitted::T t;
  t.m = 0;
  return 0;
}

