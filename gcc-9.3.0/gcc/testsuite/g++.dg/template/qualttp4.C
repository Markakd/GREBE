// Copyright (C) 2001 Free Software Foundation
// Contributed by Kriang Lerdsuwanakij <lerdsuwa@users.sourceforge.net>
// { dg-do compile }

struct A
{
	template <class T> struct B {};
};

template <template <class, class> class TT> // { dg-message "provided for" }
struct X
{
	TT<int> y; // { dg-error "number" }
};

template <class T> struct C
{
	X<T::template B> x; // { dg-error "type" }
};

int main()
{
	C<A> c; // { dg-message "required" }
}
