// PR c++/40689
// { dg-do compile { target c++11 } }

class X
{
 public:
  X(): data {1,2} {} // { dg-error "too many initializers" }
 private:
  const short data[1];
};

int f(int n)
{
  const float * pData = new const float[1] { 1.5, 2.5 }; // { dg-error "too many initializers" }

  return 0;
}
