// { dg-do assemble  }
// Error: Internal Compiler Error in 2.7.2. & egcs 1.0.0

#ifndef NO_META_MAX
template<int N1, int N2>
struct meta_max {
    enum { max = (N1 > N2) ? N1 : N2 };
};
#endif

struct X {
    enum {
       a = 0,
       n = 0
    };
};

template<class T1, class T2>
struct Y {

    enum {
       a = T1::a + T2::a,

       // NB: if the next line is changed to
       // n = (T1::n > T2::n) ? T1::n : T2::n
       // the problem goes away.

       n = meta_max<T1::n,T2::n>::max
    };
};

int z = Y<X,X>::a;
