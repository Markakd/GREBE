// { dg-do assemble  }
// Make sure we can cast to a templated type, that requires a conversion by
// constructor, from a non-aggregate type.

// prms-id: 3524

template <class T>
struct ccPair {
    ccPair (int i) { }
};

void foo ()
{
  (ccPair<float>)1;
}
