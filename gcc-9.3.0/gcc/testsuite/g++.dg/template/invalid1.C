// PR c++/14883
// { dg-options "-std=gnu++98" }

template < class T > struct DomainTraits {};
template < int Dim > class Interval;
template < class DT > class Domain {};
template <> class Interval < 1 >:public Domain < DomainTraits < Interval < 1 >
>> {}; // { dg-error "" }
