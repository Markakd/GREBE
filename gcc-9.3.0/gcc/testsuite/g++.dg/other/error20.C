// PR c++/34275
// { dg-do compile }

struct A			// { dg-message "operator=|no known conversion" }
{
  virtual A foo ();
};

void bar (A& a)
{
  a.foo () = 0; // { dg-error "operand types are 'A' and 'int'" }
}   
