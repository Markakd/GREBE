// { dg-do assemble  }
// Bug: g++ complains about a class definition containing a const member
// but no constructor; it shouldn't complain at that point, since this is
// valid use.

struct S { const int member; } object = { 0 };
