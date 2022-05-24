extern void abort (void);
typedef __SIZE_TYPE__ size_t;
extern size_t strlen(const char *);
extern char *strchr(const char *, int);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern int inside_main;
extern const char *p;

__attribute__ ((used))
char *
my_strstr (const char *s1, const char *s2)
{
  const size_t len = strlen (s2);

#ifdef __OPTIMIZE__
  /* If optimizing, we should be called only in the strstr (foo + 2, p)
     case.  All other cases should be optimized.  */
  if (inside_main)
    if (s2 != p || strcmp (s1, "hello world" + 2) != 0)
      abort ();
#endif
  if (len == 0)
    return (char *) s1;
  for (s1 = strchr (s1, *s2); s1; s1 = strchr (s1 + 1, *s2))
    if (strncmp (s1, s2, len) == 0)
      return (char *) s1;
  return (char *) 0;
}

char *
strstr (const char *s1, const char *s2)
{
  if (inside_main)
    abort ();

  return my_strstr (s1, s2);
}
