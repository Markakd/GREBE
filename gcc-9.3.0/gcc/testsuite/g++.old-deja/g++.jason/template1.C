// { dg-do assemble  }
// PRMS Id: 4688
// Bug: g++ can't deal with templates instantiated within extern "C".

class Gnaf {
public:
   virtual int invariant ();
};

template <class T> class Array : public Gnaf {
public:
   virtual int invariant();
};

extern "C"
int foo()
{
   Array<int> toConv;
   return 0;
}
