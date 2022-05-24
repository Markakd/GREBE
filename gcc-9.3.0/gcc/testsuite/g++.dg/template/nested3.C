template <class T1, class T2>
class A {
  template <class S>
  class SubA {
    int _k;
  };
  T1 _t1;
  T2 _t2;
};

template <class U>
class B {
  class SubB1 {
    B _i;
  };

  class SubB2 {
    int _j;
  };
  A<U,SubB1>::SubA<SubB2> _a; // { dg-error "not a base type" "not base" }
		// { dg-message "note" "note" { target *-*-* } .-1 }
		// { dg-error "non-template" "non-template" { target *-*-* } .-2 }
};


int main() {
  B<char> objB;

  return 0;
}
