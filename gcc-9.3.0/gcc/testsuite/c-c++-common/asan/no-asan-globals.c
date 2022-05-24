/* { dg-do compile } */
/* { dg-options "--param asan-globals=0" } */

volatile int ten = 10;

int main() {
  volatile static char XXX[10];
  XXX[ten];
  return 0;
}

/* { dg-final { scan-assembler-not "__asan_register_globals" } } */
