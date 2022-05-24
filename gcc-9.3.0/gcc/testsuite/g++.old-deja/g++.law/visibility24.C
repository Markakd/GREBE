// { dg-do assemble  }
// GROUPS passed visibility
// visibility file
// From: joe@consolve.com (Joe Shapiro)
// Date:     Fri, 20 Aug 93 17:18:18 EDT
// Subject:  Template classes seem to allow users to get at private members
// Message-ID: <9308202118.AA25599@ghana.consolve>
/*
 * private.cc
 */
extern "C" int printf (const char *, ...);

template <class T>
class A
{
public:
      void Fun() { printf( "Fun fun fun!\n" ); } // { dg-message "" } private
};


template <class T>
class B: private A<T>
{
};


class C
{
public:
    C() { _b.Fun(); }// { dg-error "" } .*

private:
    B<int> _b;
};


int main()
{
    C c;
}
