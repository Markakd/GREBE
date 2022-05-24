/* { dg-options { -nostartfiles below100.o -Tbelow100.ld -O2 } } */
/* { dg-final { scan-assembler "b\[np\] B100A\\+1,#3," } } */
/* { dg-final { scan-assembler "b\[np\] B100B\\+1,#3," } } */

typedef struct
{
  unsigned short b0:1;
  unsigned short b1:1;
  unsigned short b2:1;
  unsigned short b3:1;
  unsigned short b4:1;
  unsigned short b5:1;
  unsigned short b6:1;
  unsigned short b7:1;
  unsigned short b8:1;
  unsigned short b9:1;
  unsigned short b10:1;
  unsigned short b11:1;
  unsigned short b12:1;
  unsigned short b13:1;
  unsigned short b14:1;
  unsigned short b15:1;
} BitField;

char acDummy[0xf0] __attribute__ ((__BELOW100__));
BitField B100A __attribute__ ((__BELOW100__)) =
{
1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1};
unsigned short *pA = (unsigned short *) &B100A;
BitField B100B __attribute__ ((__BELOW100__)) =
{
0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0};
unsigned short *pB = (unsigned short *) &B100B;

char *
Do (void)
{
  if (B100A.b11)
    {
      if (B100B.b11)
	return "Fail";
      else
	return "Success";
    }
  else
    return "Fail";
}

int
main (void)
{
  return Do ()[0] == 'F';
}
