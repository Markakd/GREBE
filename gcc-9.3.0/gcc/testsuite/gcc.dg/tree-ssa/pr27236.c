/* { dg-do compile } */
/* { dg-options "-O2 -fdump-tree-optimized" } */

static inline int inline_read(volatile int *mem)
{
        return *mem;
}
__attribute__ ((noinline))
int foo_read(volatile int *mem)
{
        return inline_read(mem);
}
unsigned int foo(volatile int *mem)
{
        foo_read(mem);
        return foo_read(mem);
}

/* { dg-final { scan-tree-dump-times "foo_read" 5 "optimized" } } */
