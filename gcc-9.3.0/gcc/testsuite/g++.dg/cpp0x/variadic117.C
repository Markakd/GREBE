// { dg-do compile { target c++11 } }

template <class T> struct A { typedef T type; };

template <template <class...> class T, class... U>
void f(typename T<U...>::type);

int main()
{
  f<A,int>(42);
}
