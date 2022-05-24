/* Check if the @defs() construct preserves the correct
   layout of bitfields.  */
/* Contributed by Ziemowit Laski <zlaski@apple.com>.  */
/* { dg-options "-Wpadded" } */
/* { dg-do run } */

#include "../objc-obj-c++-shared/TestsuiteObject.m"

extern void abort(void);
extern int strcmp(const char *str1, const char *str2);
#define CHECK_IF(expr) if(!(expr)) abort()

enum Enum { one, two, three, four };

@interface Base: TestsuiteObject {
  unsigned a: 2;
  int b: 3;
  enum Enum c: 4;
  unsigned d: 5;
} /* { dg-warning "padding struct size to alignment boundary" } */
@end

@interface Derived: Base {
  signed e: 5;
  int f: 4;
  enum Enum g: 3;
} /* { dg-warning "padding struct size to alignment boundary" } */
@end
  
/* Note that the semicolon after @defs(...) is optional.  */

typedef struct { @defs(Base) } Base_t;  /* { dg-warning "padding struct size to alignment boundary" } */
typedef struct { @defs(Derived); } Derived_t;  /* { dg-warning "padding struct size to alignment boundary" } */

int main(void)
{
  CHECK_IF(sizeof(Base_t) == sizeof(Base));
  CHECK_IF(sizeof(Derived_t) == sizeof(Derived));

#ifdef __NEXT_RUNTIME__
  CHECK_IF(!strcmp(@encode(Base), "{Base=#b2b3b4b5}"));
  CHECK_IF(!strcmp(@encode(Derived), "{Derived=#b2b3b4b5b5b4b3}"));

  CHECK_IF(!strcmp(@encode(Base_t), "{?=#b2b3b4b5}"));
  CHECK_IF(!strcmp(@encode(Derived_t), "{?=#b2b3b4b5b5b4b3}"));
#endif /* __NEXT_RUNTIME__ */

  return 0;
}
