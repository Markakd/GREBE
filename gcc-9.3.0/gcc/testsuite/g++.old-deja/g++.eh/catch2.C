// { dg-do assemble  }
// Origin: Mike Danylchuk <miked@mpath.com>

typedef char TCHAR;

int main()
{
  try {}
  catch( TCHAR* Err ) {}
}

