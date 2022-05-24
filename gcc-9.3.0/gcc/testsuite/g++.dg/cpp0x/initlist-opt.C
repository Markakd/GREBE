// PR c++/41997
// { dg-do compile { target c++11 } }
// { dg-options "-O2 -fdump-tree-optimized" }
// { dg-final { scan-tree-dump-not "_0" "optimized" } }

#include <initializer_list>

inline int max_val(std::initializer_list<int> il)
{
        int i = *(il.begin());
        int j = *(il.begin() + 1);
        return (i > j ? i : j);
}

int main(void)
{
        return max_val({1,2});
}

