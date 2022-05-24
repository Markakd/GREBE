/* PR c/68657 */
/* { dg-options "-Werror=sign-conversion -Werror=float-conversion -Werror=frame-larger-than=65536" } */
/* { dg-require-effective-target ptr32plus } */

void
f1 (void)
{
  unsigned int a = -5;	/* { dg-error "unsigned conversion from .int. to .unsigned int. changes value from .-5. to .\[0-9\]+." } */
  (void) a;
}

int
f2 (void)
{
  return 3.1f;	/* { dg-error "conversion from .float. to .int. changes value" } */
}

int f3 (char *);

int
f4 (void)
{
  char buf[131072];
  return f3 (buf);
}		/* { dg-error "the frame size of 1\[0-9]* bytes is larger than 65536 bytes" } */

/* { dg-prune-output "treated as errors" } */
