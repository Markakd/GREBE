// { dg-do assemble  }
enum { a, b };

class Bug {
  int pri:8;
  int flags:15;
public:
  void bug() {
    flags |= a;   // this does not work
  }
};

void dummy(Bug x) { x.bug(); }
