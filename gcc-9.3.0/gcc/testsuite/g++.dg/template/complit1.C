// { dg-options "" }

template <int D> struct C {
  int d[3];
  C();
};

template<int D>
C<D>::C() : d((int[]){1,2,3}) {} // { dg-error "array" }

template class C<1>;
