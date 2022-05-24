/* PR c++/26698 */
/* { dg-do compile } */

struct X {
  int x;
  X (int i = 0) : x (i) {}
  operator X& (void) const { // { dg-warning "will never use" }
    return *(new X);
  }
};

void add_one (X & ref) { /* { dg-message "argument" } */
  ++ ref.x;
}

void foo() {
  X const a (2);
  add_one(a); /* { dg-error "discards qualifiers" } */
}
