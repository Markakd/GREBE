// { dg-do assemble  }
// Origin: Mark Mitchell <mark@codesourcery.com>

template <class T = int>
struct S 
{
  void g () 
    {
    }
  
  friend void f (double) 
    {
    }
};

