// { dg-do assemble }
// regression test -

// by Paul Burchard <burchard@pobox.com>, Level Set Systems, Inc.
// Copyright (C) 1999 Free Software Foundation

template<class A>
struct X {
	X(A) {
	}
};
template<class A>
struct Y {
	static X<A> x(A(1)); // { dg-error "" } ANSI C++ forbids in-class initialization of non-const static member `x'
};
Y<int> y;

