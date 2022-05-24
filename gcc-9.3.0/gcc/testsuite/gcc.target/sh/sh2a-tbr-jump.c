/* Testcase to check generation of a SH2A specific,
   TBR relative jump instruction - 'JSR @@(disp8,TBR)'.  */
/* { dg-do compile { target { sh2a } } }  */
/* { dg-options "" } */
/* { dg-final { scan-assembler-times "jsr/n\\t@@\\(40,tbr\\)" 1} } */
/* { dg-final { scan-assembler-times "jsr/n\\t@@\\(72,tbr\\)" 1} } */
 
extern void foo1 (void) __attribute__ ((function_vector(10)));
extern void foo2 (void);
extern int bar1 (void) __attribute__ ((function_vector(18)));
extern int bar2 (void);

int
bar()
{
  foo1();
  foo2();

  bar1();
  bar2();
}
