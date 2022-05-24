// PR c++/40306, c++/40307
// { dg-do run { target c++11 } }

template< typename T >
struct test {
   test run() {
      auto tmp = *this;
      return tmp;
   }
   test run_pass() {
      test tmp( *this );
      return tmp;
   }

   test run_fail() {
      auto tmp( *this );
      return tmp;
   }
};

int main()
{
   test<int> x;
   x.run();
   x.run_pass();
   x.run_fail();
   return 0;
}
