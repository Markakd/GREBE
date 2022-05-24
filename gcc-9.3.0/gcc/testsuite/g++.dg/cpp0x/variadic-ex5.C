// { dg-do compile { target c++11 } }
template<typename... Types> void f(Types... values);

void g()
{
  f<int*, float*>(0, 0, 0); // Types is deduced to the sequence int*, float*, int
}
