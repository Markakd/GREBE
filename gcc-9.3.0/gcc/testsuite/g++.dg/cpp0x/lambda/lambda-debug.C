// PR c++/43502
// { dg-do compile { target c++11 } }
// { dg-options "-fcompare-debug" }

void g (int n)
{
  int bef ([]{return 0;}());
}
struct S {
  void f (int = []{return 0;}(), int = [] { return 0;}());
};
int main ()
{
  S ().f ();
  return 0;
}
