/* { dg-do run } */
/* { dg-options "-fsanitize=vla-bound -Wall -Wno-unused-variable -fno-sanitize-recover=vla-bound" } */

int
main (void)
{
  const int t = 0;
  struct s {
    int x;
    /* Don't instrument this one.  */
    int g[t];
  };
  return 0;
}
