// PR c++/10247
// Origin: Lars Gullik Bj�nes <larsbj@lyx.org>
// { dg-do compile }

struct A {};

A const foo();

void bar()
{
    A a = foo();
    A b = true ? a : foo();
}
