// Origin: PR c++/43375
// { dg-do compile { target i?86-*-* x86_64-*-* } }
// { dg-require-effective-target c++11 }
// { dg-options "-msse2" }
// { dg-require-effective-target sse2 }

typedef float __v4sf __attribute__ ((__vector_size__ (16)));
typedef int __v4si __attribute__ ((__vector_size__ (16)));
__v4sf my_asin(__v4sf x)
{
  static const __v4si g_Mask{0x7fffffff,
			     0x00000000,
			     0x7fffffff,
			     0x7fffffff };
  return __builtin_ia32_andnps ((__v4sf) g_Mask, x);
}
