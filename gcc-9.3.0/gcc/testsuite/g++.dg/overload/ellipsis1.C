// PR c++/15142
// Bug: We were aborting after giving a warning about passing a non-POD.
// { dg-options "-Wconditionally-supported" }

struct B { 
    B() throw() { } 
    B(const B&) throw() { } 
}; 
 
struct X { 
    B a; 
    X& operator=(const X&); 
}; 
 
struct S { S(...); }; 
 
void SillyFunc() { 
  throw S(X()); 		// { dg-message "copy" }
} 
