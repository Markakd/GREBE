// { dg-do assemble  }
// GROUPS passed conversions
void f(const short & s) { }

   int
main() {
   f(0);
   return 0;
}
