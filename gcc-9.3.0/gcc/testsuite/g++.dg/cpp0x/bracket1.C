// { dg-do compile { target c++11 } }

template<typename T>
struct list {};

template<typename T>
struct vector { 
  operator T() const;
};

void f()
{
  vector<vector<int>> v;
  const vector<int> vi = static_cast<vector<int>>(v);
}
