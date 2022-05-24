// { dg-do compile }

struct S { void f (void); };

typedef void f1 (void) throw (int); // { dg-error "exception" "" { target c++14_down } }
				    // { dg-error "dynamic exception specification" "" { target c++17 } .-1 }
				    // { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } .-2 }
typedef void (*f2) (void) throw (int); // { dg-error "exception" "" { target c++14_down } }
				       // { dg-error "dynamic exception specification" "" { target c++17 } .-1 }
				       // { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } .-2 }
typedef void (S::*f3) (void) throw (int); // { dg-error "exception" "" { target c++14_down } }
					  // { dg-error "dynamic exception specification" "" { target c++17 } .-1 }
					  // { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } .-2 }
void (*f4) (void) throw (int); // { dg-error "dynamic exception specification" "" { target c++17 } }
			       // { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } .-1 }
void (S::*f5) (void) throw (int); // { dg-error "dynamic exception specification" "" { target c++17 } }
				  // { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } .-1 }
