// { dg-do assemble  }

template <int I>
struct S {};

template <int J>
void foo(S<J + 2>);		// { dg-message "note" }

void bar()
{
  foo(S<3>()); // { dg-error "" } no way to deduce J from this.
  // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
}
