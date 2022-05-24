// { dg-do compile { target c++11 } }
template<typename T>
struct vector { 
};

struct X {
  template<typename T>
  struct tmpl { 
    operator T() const;
  };
};

template<typename T>
void g()
{
  T::template tmpl<vector<int>>() + 2;
}

template<typename T>
void operator+(vector<T>, int);

void f()
{
  vector<vector<int>>() + 2;
}

// PR c++/36460
template <class a>
class A {};
template <class b>
class B {};

A<B<void()>> x;

