/* PR middle-end/89210 */
/* { dg-do compile } */
/* { dg-options "-O2" } */

typedef int v4si __attribute__((vector_size (4 * sizeof (int))));
typedef double v4df __attribute__((vector_size (4 * sizeof (double))));
void
foo (v4df *x)
{
  v4si a = { 1, 2, 3, 4 };
  *x = __builtin_convertvector (a, v4df);
}
