/* { dg-do compile } */
/* { dg-options "-O2 -mcrc32 -std=gnu89" } */
/* { dg-final { scan-assembler "crc32q\[^\\n\]*rax" { target { ! ia32 } } } } */

unsigned long long
crc32d (unsigned long long x, unsigned long long y)
{
  return __builtin_ia32_crc32di (x, y);
}
