/* Test structures passed by value, including to a function with a
   variable-length argument lists.  All struct members are of type
   _Complex float.  */
/* { dg-skip-if "Program too big" { "avr-*-*" } } */

extern void struct_by_value_16_x (void);
extern void exit (int);
int fails;

int
main ()
{
  struct_by_value_16_x ();
  exit (0);
}
