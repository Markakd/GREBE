// { dg-do assemble  }
// Yet Another testcase for signed/unsigned enums.

enum A { AA = 0, AB = 1};
enum B { BA = -1, BB = 1};

void set(int a);
void set(long a);

void
foo()
{
	set(AA);	// { dg-bogus "" } why is this ambiguous
	set(BA);	// when this is not amibguous
}
