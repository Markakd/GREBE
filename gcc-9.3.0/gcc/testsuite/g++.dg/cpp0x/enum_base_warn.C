// { dg-do run { target c++11 } }
// { dg-options "-O2 -Wtype-limits" }
extern void link_error (void);

enum Alpha : unsigned char {
 ZERO = 0, ONE, TWO, THREE
};

Alpha a2;

int m1 = -1;
int GetM1() {
 return m1;
}

int main() {
 a2 = static_cast<Alpha>(GetM1());
 if (a2 == -1) {	// { dg-warning "always false due" }
    link_error ();
 }
 if (-1 == a2) {	// { dg-warning "always false due" }
    link_error ();
 }
 return 0;
}
