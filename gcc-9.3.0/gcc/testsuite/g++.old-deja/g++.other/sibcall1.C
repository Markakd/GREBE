// { dg-do run  }
// { dg-options "-O2" }

#include <iostream>

std::ostream& foo (const char *x, std::ostream &y)
{
  return y << "" << x;
}

int main ()
{
  foo ("", std::cout);
}
