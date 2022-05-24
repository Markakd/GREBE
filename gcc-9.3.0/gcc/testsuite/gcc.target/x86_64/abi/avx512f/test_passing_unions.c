#include "avx512f-check.h"
#include "args.h"

struct IntegerRegisters iregs;
struct FloatRegisters fregs;
unsigned int num_iregs, num_fregs;

union un1
{
  __m512 x;
  float f;
};

union un2
{
  __m512 x;
  double d;
};

union un3
{
  __m512 x;
  __m128 v;
};

union un4
{
  __m512 x;
  long double ld;
};

union un5
{
  __m512 x;
  int i;
};

union un6
{
  __m512 x;
  __m256 v;
};


void
check_union_passing1(union un1 u1 ATTRIBUTE_UNUSED,
		     union un1 u2 ATTRIBUTE_UNUSED,
		     union un1 u3 ATTRIBUTE_UNUSED,
		     union un1 u4 ATTRIBUTE_UNUSED,
		     union un1 u5 ATTRIBUTE_UNUSED,
		     union un1 u6 ATTRIBUTE_UNUSED,
		     union un1 u7 ATTRIBUTE_UNUSED,
		     union un1 u8 ATTRIBUTE_UNUSED)
{
  /* Check register contents.  */
  check_m512_arguments;
}

void
check_union_passing2(union un2 u1 ATTRIBUTE_UNUSED,
		     union un2 u2 ATTRIBUTE_UNUSED,
		     union un2 u3 ATTRIBUTE_UNUSED,
		     union un2 u4 ATTRIBUTE_UNUSED,
		     union un2 u5 ATTRIBUTE_UNUSED,
		     union un2 u6 ATTRIBUTE_UNUSED,
		     union un2 u7 ATTRIBUTE_UNUSED,
		     union un2 u8 ATTRIBUTE_UNUSED)
{
  /* Check register contents.  */
  check_m512_arguments;
}

void
check_union_passing3(union un3 u1 ATTRIBUTE_UNUSED,
		     union un3 u2 ATTRIBUTE_UNUSED,
		     union un3 u3 ATTRIBUTE_UNUSED,
		     union un3 u4 ATTRIBUTE_UNUSED,
		     union un3 u5 ATTRIBUTE_UNUSED,
		     union un3 u6 ATTRIBUTE_UNUSED,
		     union un3 u7 ATTRIBUTE_UNUSED,
		     union un3 u8 ATTRIBUTE_UNUSED)
{
  /* Check register contents.  */
  check_m512_arguments;
}

void
check_union_passing4(union un4 u ATTRIBUTE_UNUSED)
{
   /* Check the passing on the stack by comparing the address of the
      stack elements to the expected place on the stack.  */
  assert ((unsigned long)&u.x == rsp+8);
  assert ((unsigned long)&u.ld == rsp+8);
}

void
check_union_passing5(union un5 u ATTRIBUTE_UNUSED)
{
   /* Check the passing on the stack by comparing the address of the
      stack elements to the expected place on the stack.  */
  assert ((unsigned long)&u.x == rsp+8);
  assert ((unsigned long)&u.i == rsp+8);
}

void
check_union_passing6(union un6 u1 ATTRIBUTE_UNUSED,
		     union un6 u2 ATTRIBUTE_UNUSED,
		     union un6 u3 ATTRIBUTE_UNUSED,
		     union un6 u4 ATTRIBUTE_UNUSED,
		     union un6 u5 ATTRIBUTE_UNUSED,
		     union un6 u6 ATTRIBUTE_UNUSED,
		     union un6 u7 ATTRIBUTE_UNUSED,
		     union un6 u8 ATTRIBUTE_UNUSED)
{
  /* Check register contents.  */
  check_m512_arguments;
}

#define check_union_passing1 WRAP_CALL(check_union_passing1)
#define check_union_passing2 WRAP_CALL(check_union_passing2)
#define check_union_passing3 WRAP_CALL(check_union_passing3)
#define check_union_passing4 WRAP_CALL(check_union_passing4)
#define check_union_passing5 WRAP_CALL(check_union_passing5)
#define check_union_passing6 WRAP_CALL(check_union_passing6)

static void
avx512f_test (void)
{
  union un1 u1[8];
  union un2 u2[8];
  union un3 u3[8];
  union un4 u4;
  union un5 u5;
  union un6 u6[8];
  int i;

  for (i = 0; i < 8; i++)
    u1[i].x = (__m512){32+i, 0, i, 0, -i, 0, i - 12, i + 8,
		       32+i, 0, i, 0, -i, 0, i - 12, i + 8};

  clear_struct_registers;
  for (i = 0; i < 8; i++)
    (&fregs.zmm0)[i]._m512[0] = u1[i].x;
  num_fregs = 8;
  check_union_passing1(u1[0], u1[1], u1[2], u1[3],
		       u1[4], u1[5], u1[6], u1[7]);

  clear_struct_registers;
  for (i = 0; i < 8; i++)
    {
      u2[i].x = u1[i].x;
      (&fregs.zmm0)[i]._m512[0] = u2[i].x;
    }
  num_fregs = 8;
  check_union_passing2(u2[0], u2[1], u2[2], u2[3],
		       u2[4], u2[5], u2[6], u2[7]);

  clear_struct_registers;
  for (i = 0; i < 8; i++)
    {
      u3[i].x = u1[i].x;
      (&fregs.zmm0)[i]._m512[0] = u3[i].x;
    }
  num_fregs = 8;
  check_union_passing3(u3[0], u3[1], u3[2], u3[3],
		       u3[4], u3[5], u3[6], u3[7]);

  check_union_passing4(u4);
  check_union_passing5(u5);

  clear_struct_registers;
  for (i = 0; i < 8; i++)
    {
      u6[i].x = u1[i].x;
      (&fregs.zmm0)[i]._m512[0] = u6[i].x;
    }
  num_fregs = 8;
  check_union_passing6(u6[0], u6[1], u6[2], u6[3],
		       u6[4], u6[5], u6[6], u6[7]);
}
