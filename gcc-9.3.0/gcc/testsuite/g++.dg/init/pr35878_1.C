// PR c++/35878
// { dg-do compile }
// { dg-options "-O2 -std=gnu++11 -fdump-tree-optimized" }
// { dg-final { scan-tree-dump-not "v_\[0-9]+\\(D\\) \[=!]= 0" "optimized" } }

#include <new>
#include <utility>

struct s1{
  int a;
  int b;
  int c;
};

void f1 (s1 * v, s1&& s)
{
	new (v) s1(std::move(s));
}

void f2 (s1 * v, s1&& s)
{
	*v = std::move(s);
}
