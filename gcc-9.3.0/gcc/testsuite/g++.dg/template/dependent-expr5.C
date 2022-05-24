// { dg-do compile }

// Copyright 2005 Free Software Foundation
// contributed by Alexandre Oliva <aoliva@redhat.com>
// inspired in the failure reported in Red Hat bugzilla #168260.

template<class F> void bind(F f) {} // { dg-message "note" }

template<class F> void bindm(F f) {} // { dg-message "note" }
template<class F, class T> void bindm(F (T::*f)(void)) {} // { dg-message "note" }

template<class F> void bindn(F f) {}
template<class F, class T> void bindn(F (*f)(T)) {}

template<class F> void bindb(F f) {}
template<class F, class T> void bindb(F (*f)(T)) {} // { dg-message "note" }
template<class F, class T> void bindb(F (T::*f)(void)) {} // { dg-message "note" }

struct foo {
  static int baist;
  int bait;			// { dg-message "" }
  void barf ();
  static void barf (int);

  struct bar {
    static int baikst;
    int baikt;
    void bark ();
    static void bark (int);

    bar() {
      bind (&baist);
      bind (&foo::baist);
      bind (&bait); // { dg-error "non-static data member" }
      bind (&foo::bait);

      bind (&baikst);
      bind (&bar::baikst);
      bind (&baikt); // ok, this->baikt
      bind (&bar::baikt);

      bind (&barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bind (&foo::barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }

      bindm (&barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bindm (&foo::barf);

      bindn (&barf);
      bindn (&foo::barf);

      bindb (&barf);
      bindb (&foo::barf); // { dg-error "ambiguous" }


      bind (&bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bind (&bar::bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }

      bindm (&bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bindm (&bar::bark);

      bindn (&bark);
      bindn (&bar::bark);

      bindb (&bark);
      bindb (&bar::bark); // { dg-error "ambiguous" }

    }
  };

  template <typename T>
  struct barT {
    static int baikst;
    int baikt;
    void bark ();
    static void bark (int);

    barT() {
      bind (&baist);
      bind (&foo::baist);
      bind (&bait); // { dg-error "non-static data member" }
      bind (&foo::bait);

      bind (&baikst);
      bind (&barT::baikst);
      bind (&baikt); // ok, this->baikt
      bind (&barT::baikt);

      bind (&barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bind (&foo::barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }

      bindm (&barf); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bindm (&foo::barf);

      bindn (&barf);
      bindn (&foo::barf);

      bindb (&barf);
      bindb (&foo::barf); // { dg-error "ambiguous" }


      bind (&bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bind (&barT::bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }

      bindm (&bark); // { dg-error "no matching function" }
      // { dg-message "(candidate|deduce template parameter)" "candidate note" { target *-*-* } .-1 }
      bindm (&barT::bark);

      bindn (&bark);
      bindn (&barT::bark);

      bindb (&bark);
      bindb (&barT::bark); // { dg-error "ambiguous" }

    }
  };

  bar bard;
  barT<void> bart;
} bad;
