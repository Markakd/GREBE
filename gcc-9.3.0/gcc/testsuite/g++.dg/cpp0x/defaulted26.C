// PR c++/49066
// { dg-do compile { target c++11 } }

void foo() = delete;		// { dg-message "declared here" }
void foo();

int main() { foo(); }		// { dg-error "deleted" }
