// PR c++/49593
// { dg-do compile { target c++11 } }

template<typename... T> void f(T...) { }

template<typename... Args>
static void
g(Args&&... args)
{
  f( static_cast<Args>(args)... );
  f( (Args)args... );
  f( Args(args)... );
  f( Args{args}... );
}

int main()
{
  g(1, '2', 3.0);
}
