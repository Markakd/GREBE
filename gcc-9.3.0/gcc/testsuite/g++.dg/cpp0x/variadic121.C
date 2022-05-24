// PR c++/51507
// { dg-do compile { target c++11 } }

template<typename ...>
struct foo { typedef void type; };
template<typename ...Ts>
auto g(Ts ...ts)->
  typename foo<decltype(ts)...>::type
{}
int main() {
  g(42);
}
