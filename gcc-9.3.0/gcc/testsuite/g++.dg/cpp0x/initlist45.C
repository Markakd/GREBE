// PR c++/46289
// { dg-do compile { target c++11 } }

struct A
{
  int i[2];
};

struct B
{
  A a;
  B(): a({{1,2}}) { }
};
