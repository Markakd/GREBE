// { dg-do assemble  }
// Test to make sure that value return of classes with cleanups works; it
// has been broken at various times on PCC_STATIC_STRUCT_RETURN targets.

struct A {};

struct R : virtual A { virtual ~R(); };

R g();

void encode()
{
    g();
}
