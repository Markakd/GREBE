// { dg-do link { target c++11 } }

template<typename _Tp>
inline _Tp&&
movel(_Tp& __t)
{ return static_cast<_Tp&&>(__t); }

struct S {};
struct T
{
  T(S && s_) : s(movel(s_)) {}
  S && get() { return movel(s); }
  operator S&&() { return movel(s); }
  S && s;
  S s2;
};

void named(S const &) {}
void named(S&&);

void unnamed(S const &);
void unnamed(S&&) {}

void f(S && p)
{
  S && s(movel(p));
  T t(movel(s));

  named(s);                          // variable reference
  named(p);                          // parameter reference
  named(t.s);                        // class member access

  unnamed(t.get());                  // function return
  unnamed(t);                        // implicit conversion
  unnamed(static_cast<S&&>(s));      // cast to rvalue
  unnamed(static_cast<T&&>(t).s2);   // cast to rvalue
}

int main()
{
}
