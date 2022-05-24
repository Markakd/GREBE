// PR c++/47774
// { dg-do compile { target c++11 } }

struct A
{
  A() {}
};

template <typename T>
struct array
{
  constexpr array() : mem() {}
  T mem[7];
};

int main()
{
  array<A> ar;
}
