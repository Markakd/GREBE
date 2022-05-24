/* { dg-do run } */

#include <stdio.h>

#include "init5.h"
#include "dump.h"

int main (void)
{
  struct R1 Local_R1;
  struct R2 Local_R2;

  put ("My_R1    :");
  dump (&My_R1, sizeof (struct R1));
  new_line ();
  /* { dg-output "My_R1    : 78 56 34 12 12 00 ab 00 34 00 cd 00 56 00 ef 00.*\n" } */

  put ("My_R2    :");
  dump (&My_R2, sizeof (struct R2));
  new_line ();
  /* { dg-output "My_R2    : 12 34 56 78 00 ab 00 12 00 cd 00 34 00 ef 00 56.*\n" } */

  Local_R1 = My_R1;
  put ("Local_R1 :");
  dump (&Local_R1, sizeof (struct R1));
  new_line ();
  /* { dg-output "Local_R1 : 78 56 34 12 12 00 ab 00 34 00 cd 00 56 00 ef 00.*\n" } */

  Local_R2 = My_R2;
  put ("Local_R2 :");
  dump (&Local_R2, sizeof (struct R2));
  new_line ();
  /* { dg-output "Local_R2 : 12 34 56 78 00 ab 00 12 00 cd 00 34 00 ef 00 56.*\n" } */

  Local_R1.I    = 0x12345678;
  Local_R1.A[0] = 0xAB0012;
  Local_R1.A[1] = 0xCD0034;
  Local_R1.A[2] = 0xEF0056;
  put ("Local_R1 :");
  dump (&Local_R1, sizeof (struct R1));
  new_line ();
  /* { dg-output "Local_R1 : 78 56 34 12 12 00 ab 00 34 00 cd 00 56 00 ef 00.*\n" } */

  Local_R2.I    = 0x12345678;
  Local_R2.A[0] = 0xAB0012;
  Local_R2.A[1] = 0xCD0034;
  Local_R2.A[2] = 0xEF0056;
  put ("Local_R2 :");
  dump (&Local_R2, sizeof (struct R2));
  new_line ();
  /* { dg-output "Local_R2 : 12 34 56 78 00 ab 00 12 00 cd 00 34 00 ef 00 56.*\n" } */

  Local_R1.I    = Local_R2.I;
  Local_R1.A[0] = Local_R2.A[0];
  Local_R1.A[1] = Local_R2.A[1];
  Local_R1.A[2] = Local_R2.A[2];

  put ("Local_R1 :");
  dump (&Local_R1, sizeof (struct R1));
  new_line ();
  /* { dg-output "Local_R1 : 78 56 34 12 12 00 ab 00 34 00 cd 00 56 00 ef 00.*\n" } */

  Local_R2.I    = Local_R1.I;
  Local_R2.A[0] = Local_R1.A[0];
  Local_R2.A[1] = Local_R1.A[1];
  Local_R2.A[2] = Local_R1.A[2];

  put ("Local_R2 :");
  dump (&Local_R2, sizeof (struct R2));
  new_line ();
  /* { dg-output "Local_R2 : 12 34 56 78 00 ab 00 12 00 cd 00 34 00 ef 00 56.*\n" } */

  new_line ();
  return 0;
}
