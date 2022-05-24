// PR c++/48736
// { dg-do compile { target c++11 } }

template<class T>
T&& create();

template<class T, class... Args,
 class = decltype(T{create<Args>()...}) // Line X
>
char f(int);
