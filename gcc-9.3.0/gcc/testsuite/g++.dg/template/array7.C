// PR c++/16246

template <typename T> void foo (T, T); 
 
template <unsigned N, unsigned M>  
int bar( const char(&val)[M] ) 
{ 
  foo (N,M); 
  return 0;
} 
 
int i = bar<10>("1234"); 
