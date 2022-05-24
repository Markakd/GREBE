// { dg-do run { target c++11 } }

auto f = [](int i) { return i+1; };

int g(int i = [] { return 237; }())
{
  return i;
}

int main()
{
  if (f(41) != 42)
    return 1;
  if (g() != 237)
    return 2;
  return 0;
}
