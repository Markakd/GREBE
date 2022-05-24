// { dg-do assemble  }
// Bug: the SAVE_EXPR in the new expression remembers that it's in g(),
// causing the compiler to crash in h().


struct A {
  A ();
};

void f (A* = new A);

void g ()
{
  f ();
}

void h ()
{
  f ();
}
