// PR 14535
// { dg-do run }
// { dg-options "-O -finline" }
//
// Original test case failure required that Raiser constructor be inlined.

extern "C" void abort(); 
bool destructor_called = false; 
 
struct B { 
    virtual void Run(){}; 
}; 
 
struct D : public B { 
    virtual void Run() 
      { 
        struct O { 
            ~O() { destructor_called = true; }; 
        } o; 
         
        struct Raiser { 
            Raiser()
#if __cplusplus <= 201402L
	    throw( int )			// { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } }
#endif
	    {throw 1;}; 
        } raiser; 
      }; 
}; 
 
int main() { 
    try { 
      D d; 
      static_cast<B&>(d).Run(); 
    } catch (...) {} 
 
    if (!destructor_called) 
      abort (); 
} 
