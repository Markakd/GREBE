/* { dg-do compile } */

struct Vector
{
    double _x, _y;
};
typedef Vector Point;
Vector d;
static inline Vector f(void)
{
  return d;
}
void add_duck (void)
{
    new Point (f());
}
