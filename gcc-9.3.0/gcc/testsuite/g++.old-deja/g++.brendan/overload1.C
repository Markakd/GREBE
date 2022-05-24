// { dg-do assemble  }
// GROUPS passed overloading
class Foo
{
public:
  int f (void);
};

class Bar : public Foo
{
public:
      int f (int); // { dg-message "Bar::f|candidate expects" }
};

int main ()
{
  Bar b;

  b.f ();// { dg-error "no matching" } 
  b.f (10);
}
