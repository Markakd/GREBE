// PR c++/57408
// { dg-do compile { target c++11 } }
// { dg-options "-Wno-vla" }

template<typename Callable>
  struct Impl
  {
    Callable func;
    Impl(Callable f) : func(f) { }
    virtual void run() { func(); }
  };

template<typename Callable>
void call(Callable f)
  {
    Impl<Callable>(f).run();
  }

extern "C" int printf(const char*, ...);

int main(){
    int y = 2;
    float fa[2][y];
    fa[0][0]=0.8;
    fa[0][1]=1.8;
    auto fx=[&](){
        for(int c=0; c<2; c++){
            printf("use me", fa[0][c]);	// { dg-prune-output "sorry" }
        }
    };
    call(fx);
}
