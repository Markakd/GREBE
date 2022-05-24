/* Test diagnostics for duplicate label declarations.  */
/* Origin: Joseph Myers <joseph@codesourcery.com> */
/* { dg-do compile } */
/* { dg-options "" } */

void
f (void)
{
  __label__ a, b, a; /* { dg-error "duplicate label declaration 'a'" } */
  /* { dg-message "note: previous declaration of 'a' was here" "previous" { target *-*-* } .-1 } */
  __label__ c; /* { dg-message "note: previous declaration of 'c' was here" } */
  __label__ c; /* { dg-error "duplicate label declaration 'c'" } */
  return;
}
