// { dg-do assemble  }

class X;

class A {
public:
  void handlerFn(X*);
};

typedef void (A::*handler) (X*);

class B {
public:
  void setHandler(handler);
};

void f(B* b) {
  b->setHandler(A::handlerFn);	// { dg-error "" } 
}
