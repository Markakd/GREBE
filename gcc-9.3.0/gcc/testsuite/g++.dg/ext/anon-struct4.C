// PR c++/14401

struct { struct { int& i ; } bar ; } foo ; // { dg-error "deleted|uninitialized" "uninit" }
// { dg-warning "unnamed" "anon" { target { ! c++11 } } .-1 }
// { dg-message "should be initialized" "ref-uninit" { target { ! c++11 } } .-2 }
