/* { dg-do compile } */
/* { dg-options "-O -mriscv-attribute -march=rv32g2p0 -mabi=ilp32" } */
int foo()
{
}
/* { dg-final { scan-assembler ".attribute arch, \"rv32i2p0_m2p0_a2p0_f2p0_d2p0\"" } } */
