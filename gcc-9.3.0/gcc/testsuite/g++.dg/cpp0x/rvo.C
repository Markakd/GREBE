// { dg-do run { target c++11 } }
// Contributed by Sylvain Pion
static int rvalue_constructions = 0;

struct A {
  A ()         { }
  A (const A&) { }
  A (A&&)      { ++rvalue_constructions; }
  ~A ()        { }
};

A f() {  return A(); }

extern "C" {
  void abort(void);
}

int main()
{
  A c = f();

  if (rvalue_constructions != 0)
    abort();
}
