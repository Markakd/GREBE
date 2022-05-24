// { dg-do assemble  }
// { dg-options "-Wsign-promo" }
// 981203 bkoz
// g++/15756  test2
// this test may only be valid for 32bit targets at present

#include <limits.h>

enum e_i {
  vali
}
enum_int;

enum e_ui {
#if INT_MAX == 32767
  valui = 0xF234
#else
  valui = 0xF2345678
#endif
}
enum_uint;
 
int i;
unsigned int ui;

struct caracas {
  caracas(int);
  caracas(unsigned int);
  void foo();
};
 
int main ()
{
  caracas obj_ei  ( enum_int  ); // { dg-warning "" } 
  caracas obj_eui ( enum_uint ); // { dg-warning "" } 
  caracas obj_i  ( i  );
  caracas obj_ui ( ui );
  
  obj_ei.foo();
  obj_eui.foo();
  obj_i.foo();
  obj_ui.foo();
}
 






