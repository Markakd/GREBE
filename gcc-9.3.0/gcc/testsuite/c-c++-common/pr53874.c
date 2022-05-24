/* PR c/53874 */
/* { dg-do compile } */
/* { dg-options "-Wswitch-enum" } */

enum E { A, B, C };
struct S { enum E e:2; };
typedef struct S TS;

int
fn0 (struct S *s)
{
  switch (s->e) /* { dg-warning "enumeration value .C. not handled in switch" } */
    {
    case A:
      return 1;
    case B:
      return 2;
    default:
      return 0;
    }
}

int
fn1 (TS *s)
{
  switch (s->e) /* { dg-warning "enumeration value .C. not handled in switch" } */
    {
    case A:
      return 1;
    case B:
      return 2;
    default:
      return 0;
    }
}
