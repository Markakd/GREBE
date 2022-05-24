// PR c++/41090
// { dg-do run }
// { dg-options "" }
// { dg-require-effective-target indirect_jumps }

int i;
struct C
{
  C();
};

C::C()	// { dg-bogus "can never be copied" }
{
  static void *labelref = &&label;
  goto *labelref;
 label: i = 1;
}

int main()
{
  C c;
  return (i != 1);
}
