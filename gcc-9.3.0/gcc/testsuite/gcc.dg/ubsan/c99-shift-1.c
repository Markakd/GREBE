/* { dg-do run } */
/* { dg-options "-fsanitize=shift -w -std=c99" } */

int
main (void)
{
  int a = -42;
  a << 1;
}
/* { dg-output "left shift of negative value -42" } */
