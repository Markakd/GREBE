/* { dg-do compile } */
/* { dg-options "-ansi -maltivec" } */

#include <altivec.h>
vector char bool _0 ;
vector bool char _8 ;
vector char unsigned _56 ;
vector unsigned char _64 ;
vector char signed _112 ;
vector signed char _120 ;
/* bool is permitted in the predefine method, as it is expanded
   unconditionally to int.  */
bool _168 ;
vector pixel _170 ;
vector int bool _178 ;
vector bool int _186 ;
vector short bool _234 ;
vector bool short _242 ;
vector unsigned int _290 ;
vector int unsigned _298 ;
vector unsigned short _346 ;
vector short unsigned _354 ;
vector signed int _402 ;
vector int signed _410 ;
vector signed short _458 ;
vector short signed _466 ;
vector int bool _514 ;
vector int bool _544 ;
vector int bool _559 ;
vector bool int _589 ;
vector int short bool _874 ;
vector int bool short _889 ;
vector short int bool _904 ;
vector short bool int _919 ;
vector bool int short _934 ;
vector bool short int _949 ;
vector unsigned int _1234 ;
vector int unsigned _1249 ;
vector unsigned int _1279 ;
vector int unsigned _1294 ;
vector unsigned int _1309 ;
vector int unsigned short _1594 ;
vector int short unsigned _1609 ;
vector unsigned int short _1624 ;
vector unsigned short int _1639 ;
vector short int unsigned _1654 ;
vector short unsigned int _1669 ;
vector signed int _1954 ;
vector int signed _1969 ;
vector signed int _1999 ;
vector int signed _2014 ;
vector signed int _2029 ;
vector int signed short _2314 ;
vector int short signed _2329 ;
vector signed int short _2344 ;
vector signed short int _2359 ;
vector short int signed _2374 ;
vector short signed int _2389 ;
vector float _2674 ;
