// { dg-do compile { target c++11 } }

template<class T>
T&& create();

template <class T, class U,
	  class = decltype(create<T>() = create<U>())
	  >
char test(int);

template <class, class>
double test(...);

int main() {
  test<int[], int[]>(0); // #1
}
