// { dg-do run  }
extern "C" void abort ();

template <class T> void f ();
template <class T> void g ()
{
  abort ();
}

template <> void g<char> ()
{
  abort ();
}

template <class T> class C
{
  public:
    template <class U> void f () {}
    template <class U> void g () {}
    void ff () { f<T> (); }
    void gg () { g<T> (); }
};

template <class T> void f ()
{
  abort ();
}

template <> void f<char> ()
{
  abort ();
}

int main ()
{
  C<int> c;
  c.ff();
  c.gg();
  C<char> d;
  d.ff();
  d.gg();
}
