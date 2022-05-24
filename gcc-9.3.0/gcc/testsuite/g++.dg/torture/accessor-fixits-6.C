// PR c++/84994
/* Ensure that fix-it hints are offered at every optimization level, even when
   "-g" is enabled (coverage for every optimization level without -g is given
   by the other cases within g++.dg/torture/accessor-fixits-*.C).  */
// { dg-additional-options "-g" }

class foo
{
public:
  double get_ratio() const { return m_ratio; }

private:
  double m_ratio; // { dg-line field_decl }
};

void test(foo *ptr)
{
  if (ptr->m_ratio >= 0.5) // { dg-error "'double foo::m_ratio' is private within this context" }
    ;
  // { dg-message "declared private here" "" { target *-*-* } field_decl }
  // { dg-message "'double foo::m_ratio' can be accessed via 'double foo::get_ratio\\(\\) const'" "" { target *-*-* } .-3 }
}
