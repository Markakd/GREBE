// { dg-do assemble }

// by Paul Burchard <burchard@pobox.com>, Level Set Systems, Inc.
// Copyright (C) 1999 Free Software Foundation

struct Q {
	template<class>
	class X {
	};
};
template<template<class> class>
class Y {
};
Y<Q::X> y1;

