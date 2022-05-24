// PR c++/60033
// { dg-do compile { target c++14 } }

template <typename... T>
auto f(T&&... ts)
{
   return sizeof...(ts);
}

template <typename... T>
auto g(T&&... ts) {
  return [&] (auto v) {
    return f(ts...);
  };
}

int main()
{
   return g(1,2,3,4)(5) == 4 ? 0 : 1;
}
