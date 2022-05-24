// { dg-do compile { target c++11 } }
template<typename... Types> struct Tuple { };

Tuple<> t0; // Types contains no arguments
Tuple<int> t1; // Types contains one argument: int
Tuple<int, float> t2; // Types contains two arguments: int and float
Tuple<0> error; // { dg-error "mismatch" "mismatch" }
// { dg-message "expected a type" "expected a type" { target *-*-* } .-1 }
