// { dg-do assemble  }

// Copyright (C) 2000 Free Software Foundation, Inc.
// Contributed by Theodore.Papadopoulo 23 Jun 2000 <Theodore.Papadopoulo@sophia.inria.fr>

int count (int);
void *count (char *, char);

void foo(const char*,...);

inline void
bar() {
  foo("",count);    //  { dg-error "overloaded function" "multiple overloaded functions" }
}
