// { dg-do assemble  }
// Origin: robt@flyingpig.com

class Outer
{
  friend void f1(); 
  class Inner2;
};

class Outer::Inner2
{
};
