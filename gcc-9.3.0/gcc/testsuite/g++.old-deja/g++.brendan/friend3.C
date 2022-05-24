// { dg-do assemble  }
// GROUPS passed friends
class B {

   friend class A;

   enum {
      bEnum = 1, // { dg-error "comma at end" "" { target { ! c++11 } } }
   };

   int bArray[ bEnum ];

public:
   void bFunction(int arg[ bEnum ]);
};


class A {
   int aMember;

public:
   void aFunction(int a[B::bEnum])
   {
      B b;
      b.bArray[ B::bEnum ] = aMember;
   }
};

