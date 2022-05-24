// { dg-do assemble  }
template <class T>
class C;

template <class T>
struct S
{
  template <class U>
  void f(U u)
    {
      C<U> cu;
      cu.i = 3; // { dg-error "" } S<double>::f<U> is a friend, but this is
                //         S<int>::f<double>. 
    }
};


template <class T>
class C
{
  template <class U>
  friend void S<T>::f(U);

  int i; // { dg-message "" } private
};


int main()
{
  S<int> si;
  si.f(3.0);
}
