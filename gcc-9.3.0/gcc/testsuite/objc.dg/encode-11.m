/* { dg-do run } */

extern void _exit(int);
extern int strcmp(const char *, const char *);

typedef struct Vec {
 double xv[10], yv[5];
 float fscal;
 int z;
} xyz_t ;

typedef struct {
  float fscalar;
  double dscalar;
  xyz_t dv;
  int iscalar;
  long ln;
  long long lln;
} anonymous;

const char *enc = @encode(xyz_t);
const char *enc2 = @encode(anonymous);

#ifdef __LP64__
#define L "q"
#else
#define L "l"
#endif

int main(void) {
  const char *encode = @encode(long);

  if (strcmp (encode, L))
    _exit(-(__LINE__));

  if (strcmp (enc, "{Vec=[10d][5d]fi}"))
    _exit(-(__LINE__));

  if (strcmp (enc2, "{?=fd{Vec=[10d][5d]fi}i" L "q}"))
    _exit(-(__LINE__));

  return 0;
}
