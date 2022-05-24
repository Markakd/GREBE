#include <string.h>

/* { dg-final { scan-assembler "\.rodata*" } } */
/* { dg-final { scan-assembler "\.data*" } } */
const char *string1 = "string1";

char* testfunc (char *cptr)
{
/* { dg-final { scan-assembler-not "\lwi\tr(\[0-9]\|\[1-2]\[0-9]\|3\[0-1]),r13" } } */
    strcpy (cptr, string1);

    return cptr;
}
