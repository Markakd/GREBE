/* PR c/11995 */
/* The following test used to ICE after an error message
   because GCC was trying to expand the trees to rtl.  */

/* { dg-do compile } */
/* { dg-options "" } */

void f ()
{
 l: int; /* { dg-error "a label can only be part of a statement and a declaration is not a statement" "not stmt" } */
 /* { dg-warning "useless type name in empty declaration" "type name" { target *-*-* } .-1 } */
 /* { dg-error "label at end of compound statement" "label" { target *-*-* } .-2 } */
}
