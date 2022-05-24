/* { dg-do compile } */
/* { dg-options "-O2" } */

typedef float fp_t __attribute__((mode(SD)));

extern fp_t g(fp_t);

fp_t
bug(fp_t x)
{
    fp_t result;
    int n;
    fp_t f, f3, y, z;

    n = 0;
    y = 1.DF;
    f = g(x);

    if (f < 0.DF)
        f = -f;

    f3 = 2.DF;

    z = (y + y + f / (y * y));
    y = (z + z) / (9.DF) + f3 / (z * z);

    result = y;

    return (result);
}
