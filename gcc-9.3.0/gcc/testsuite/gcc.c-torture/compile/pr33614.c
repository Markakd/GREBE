typedef float V2SF __attribute__ ((vector_size (8)));

V2SF
foo (int x, V2SF a)
{
  while (x--)
    a += (V2SF) {1.0f/0.0f - 1.0f/0.0f, 1.0f/0.0f - 1.0f/0.0f};
  return a;
}
