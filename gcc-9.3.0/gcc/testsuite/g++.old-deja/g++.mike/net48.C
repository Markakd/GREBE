// { dg-do assemble  }

const char *a="a�";

class A
{
public:
	A()
	{
		const char *b="a�";
	}
};

const char *c="a�";
