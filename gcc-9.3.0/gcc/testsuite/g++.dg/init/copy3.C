// { dg-do run { target c++14_down } }
// { dg-options "-fno-elide-constructors" }

int copies;

struct S { 
  S () {}
  S (const S&) { ++copies; }
};

S s[1] = { S () };

int main () {
  if (copies != 1)
    return 1;
}
