// { dg-do compile }
// { dg-options "-Os -fprofile-use -Wno-missing-profile" }

int a;
int fn1 () { return a == ',' || a == ';'; }

void fn2 ()
{
    do
          while (fn1 ())
	          ;
      while (1);
}
