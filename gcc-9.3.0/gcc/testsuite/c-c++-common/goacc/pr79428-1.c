/* PR c/79428 */
/* { dg-options "-fopenacc" } */
void
foo ()
{
#pragma acc routine /* { dg-error ".#pragma acc routine. must be at file scope|expected" } */
