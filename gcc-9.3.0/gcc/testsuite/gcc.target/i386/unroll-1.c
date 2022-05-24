/* PR optimization/8599 */
/* { dg-do run } */
/* { dg-require-effective-target ia32 } */
/* { dg-options "-mtune=k6 -O2 -funroll-loops" } */

extern void exit (int);

void *array[4];

int main ()
{
  int i;
 
  for (i = 0; i < 4; i++)
    array[i] = 0;

  exit (0);
}
