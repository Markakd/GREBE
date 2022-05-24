// PR c++/49251
// { dg-do compile { target c++11 } }
// { dg-options "-Wunused-parameter" }

struct A {};
template <int> int f(A);

template< int... Indices >
struct indices {};

template< class... Args >
void sink( Args&&... ) {}

template< class T, int... Indices >
void unpack_test( T && t, indices<Indices...> ) {
  sink( f<Indices>(t)... );
}

int main() {
  unpack_test( A(), indices<>() );
}
