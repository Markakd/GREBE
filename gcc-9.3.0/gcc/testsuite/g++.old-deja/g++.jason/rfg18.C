// { dg-do assemble  }
// Any expression may be explicitly converted to type void.

struct S { int m[10]; } object;
struct S f () { return object; }
 
void
test ()
{
  (void) f().m;         /* OK - cast to void; see constraints in 3.8.1 */
}
