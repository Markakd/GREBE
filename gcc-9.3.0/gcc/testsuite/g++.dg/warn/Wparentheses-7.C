// { dg-do compile }
// { dg-options "-Wparentheses" }

// C++ copy of gcc.dg/Wparentheses-4.c

int foo (int);

void
bar (int a, int b, int c)
{
  foo (a + b << c); // { dg-warning "parentheses" "correct warning" }
  foo ((a + b) << c);
  foo (a + (b << c));
  foo (1 + 2 << c); // { dg-warning "parentheses" "correct warning" }
  foo ((1 + 2) << c);
  foo (1 + (2 << c));
  foo (1 + 2 << 3); // { dg-warning "parentheses" "correct warning" }
  foo ((1 + 2) << 3);
  foo (1 + (2 << 3));
  foo (a << b + c); // { dg-warning "parentheses" "correct warning" }
  foo ((a << b) + c);
  foo (a << (b + c));
  foo (1 << 2 + c); // { dg-warning "parentheses" "correct warning" }
  foo ((1 << 2) + c);
  foo (1 << (2 + c));
  foo (1 << 2 + 3); // { dg-warning "parentheses" "correct warning" }
  foo ((1 << 2) + 3);
  foo (1 << (2 + 3));
  foo (a + b >> c); // { dg-warning "parentheses" "correct warning" }
  foo ((a + b) >> c);
  foo (a + (b >> c));
  foo (1 + 2 >> c); // { dg-warning "parentheses" "correct warning" }
  foo ((1 + 2) >> c);
  foo (1 + (2 >> c));
  foo (1 + 2 >> 3); // { dg-warning "parentheses" "correct warning" }
  foo ((1 + 2) >> 3);
  foo (1 + (2 >> 3));
  foo (a >> b + c); // { dg-warning "parentheses" "correct warning" }
  foo ((a >> b) + c);
  foo (a >> (b + c));
  foo (1 >> 2 + c); // { dg-warning "parentheses" "correct warning" }
  foo ((1 >> 2) + c);
  foo (1 >> (2 + c));
  foo (1 >> 2 + 3); // { dg-warning "parentheses" "correct warning" }
  foo ((1 >> 2) + 3);
  foo (1 >> (2 + 3));
  foo (a - b << c); // { dg-warning "parentheses" "correct warning" }
  foo ((a - b) << c);
  foo (a - (b << c));
  foo (6 - 5 << c); // { dg-warning "parentheses" "correct warning" }
  foo ((6 - 5) << c);
  foo (6 - (5 << c));
  foo (6 - 5 << 4); // { dg-warning "parentheses" "correct warning" }
  foo ((6 - 5) << 4);
  foo (6 - (5 << 4));
  foo (a << b - c); // { dg-warning "parentheses" "correct warning" }
  foo ((a << b) - c);
  foo (a << (b - c));
  foo (6 << 5 - c); // { dg-warning "parentheses" "correct warning" }
  foo ((6 << 5) - c);
  foo (6 << (5 - c));
  foo (6 << 5 - 4); // { dg-warning "parentheses" "correct warning" }
  foo ((6 << 5) - 4);
  foo (6 << (5 - 4));
  foo (a - b >> c); // { dg-warning "parentheses" "correct warning" }
  foo ((a - b) >> c);
  foo (a - (b >> c));
  foo (6 - 5 >> c); // { dg-warning "parentheses" "correct warning" }
  foo ((6 - 5) >> c);
  foo (6 - (5 >> c));
  foo (6 - 5 >> 4); // { dg-warning "parentheses" "correct warning" }
  foo ((6 - 5) >> 4);
  foo (6 - (5 >> 4));
  foo (a >> b - c); // { dg-warning "parentheses" "correct warning" }
  foo ((a >> b) - c);
  foo (a >> (b - c));
  foo (6 >> 5 - c); // { dg-warning "parentheses" "correct warning" }
  foo ((6 >> 5) - c);
  foo (6 >> (5 - c));
  foo (6 >> 5 - 4); // { dg-warning "parentheses" "correct warning" }
  foo ((6 >> 5) - 4);
  foo (6 >> (5 - 4));
}
