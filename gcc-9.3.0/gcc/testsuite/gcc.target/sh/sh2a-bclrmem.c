/* Testcase to check generation of a SH2A specific instruction
   "BCLR #imm3,@(disp12,Rn)".  */
/* { dg-do compile { target { sh2a } } }  */
/* { dg-options "-O2 -mbitops" }  */
/* { dg-final { scan-assembler "bclr"} }  */
/* { dg-final { scan-assembler "bclr.b"} }  */

volatile union un_paddr
{
  unsigned char BYTE;
  struct
  {
    unsigned char B15:1;
    unsigned char B14:1;
    unsigned char B13:1;
    unsigned char B12:1;
    unsigned char B11:1;
    unsigned char B10:1;
    unsigned char B9:1;
    unsigned char B8:1;
    unsigned char B7:1;
    unsigned char B6:1;
    unsigned char B5:1;
    unsigned char B4:1;
    unsigned char B3:1;
    unsigned char B2:1;
    unsigned char B1:1;
    unsigned char B0:1;
  }
  BIT;
}
PADDR;

int
main ()
{
  PADDR.BIT.B0 = 0;
  PADDR.BIT.B3 = 0;
  PADDR.BIT.B6 = 0;

  PADDR.BIT.B1 &= 0;
  PADDR.BIT.B4 &= 0;
  PADDR.BIT.B7 &= 0;

  PADDR.BIT.B10 = 0;
  PADDR.BIT.B13 = 0;
  PADDR.BIT.B15 = 0;

  PADDR.BIT.B9 &= 0;
  PADDR.BIT.B12 &= 0;
  PADDR.BIT.B14 &= 0;

  return 0;
}
