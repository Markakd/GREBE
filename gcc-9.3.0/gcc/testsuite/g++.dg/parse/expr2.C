struct X {
  X(double *data, double d0, double d1);
};

void foo(double d0) {
  double * data;
  X(data,d0,d0);
}
