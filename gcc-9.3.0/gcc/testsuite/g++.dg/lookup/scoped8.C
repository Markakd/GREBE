// { dg-do compile }

// Origin: Volker Reichelt <reichelt@igpm.rwth-aachen.de>

// PR c++/10371: Incorrect tree node built in
// finish_non_static_data_member.

struct A
{
    int i;			// { dg-message "" }
};

template <int> struct B
{
    int foo() { return A::i; }	// { dg-error "non-static" }
};

template struct B<0>;
