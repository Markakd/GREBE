void f(int n)
{
int s;
for(s=0;s<n;s++)
  s==5?1 n=1;		/* { dg-error "parse error|syntax error|expected" } */
}
