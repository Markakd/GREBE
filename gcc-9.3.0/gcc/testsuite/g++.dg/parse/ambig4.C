// PR c++/20293

namespace hide { // { dg-message "hide" }
  int k;
}

namespace {
  int i; 
  namespace hide { // { dg-message "hide" }
    int j; 
  }
}

void F(int) {}

int main() {
  F(hide::j); // { dg-error "ambiguous" }
}
