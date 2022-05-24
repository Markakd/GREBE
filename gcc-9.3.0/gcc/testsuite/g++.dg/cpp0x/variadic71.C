// { dg-do compile { target c++11 } }
template<typename...> struct list {};

template<typename Sequence, typename Head>
struct push_front;

template<typename... Elements, typename Head>
struct push_front<list<Elements...>, Head> {
  typedef list<Head, Elements> type; // { dg-error "parameter packs not expanded" }
};

// { dg-message "Elements" "note" { target *-*-* } 9 }
