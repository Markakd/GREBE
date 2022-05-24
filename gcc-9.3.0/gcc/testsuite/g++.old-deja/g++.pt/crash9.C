// { dg-do assemble  }

template <class T>
void f(T) {}			// { dg-message "initializing" }

class C;    // { dg-message "forward declaration" }

void g(const C& c)
{
  f(c); // { dg-error "invalid use of incomplete type" }
}
