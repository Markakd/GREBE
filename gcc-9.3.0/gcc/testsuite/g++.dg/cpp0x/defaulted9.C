// PR c++/39153
// { dg-do compile { target c++11 } }
// { dg-options "-fno-inline" }

struct _Impl_base
{
  _Impl_base() = default;
  virtual ~_Impl_base();
};

inline _Impl_base::~_Impl_base() = default;

template<typename _Tp>
class _Impl : public _Impl_base
{ };

int main()
{
  _Impl<int> i;
  return 0;
}
