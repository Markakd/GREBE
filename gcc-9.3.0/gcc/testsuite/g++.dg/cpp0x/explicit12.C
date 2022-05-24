// PR c++/57728
// { dg-do link { target c++11 } }
// { dg-options -save-temps }

template<typename T>
struct A
{
  T x;
  A() = default;
  A(const A &other) = delete;
};

extern template class A<int>;

int main()
{
  A<int> a;
}

// { dg-final { scan-assembler-not "_ZN1AIiEC1Ev" } }
