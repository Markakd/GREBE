// { dg-do run  }
template<class T> class D
{
	public:
		int f();
};

template<class T> int D<T>::f()
{
	return sizeof(T);
}

template<template<class> class D,class E> class C
{
		D<E> d;
	public:
		int f() { return d.f(); }
};

template<template<class> class D,class E> int f(D<E> &d1)
{
	d1.f();
	C<D,E> d2;
	d2.f();
	return 0;
}

template<> int f<>(D<char> &d1)
{
	d1.f();
	return 0;
}

int main()
{
	D<int> c1;
	D<char> c2;
	f(c1);
	f(c2);
}
