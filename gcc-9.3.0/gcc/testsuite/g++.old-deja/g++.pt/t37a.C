// { dg-do assemble  }

class A {
public:
  A(int);
  A(float);
  ~A();
};

A::A(float f) {
}
  
A::A(int i) {
}
  
A::~A() {
}
  
