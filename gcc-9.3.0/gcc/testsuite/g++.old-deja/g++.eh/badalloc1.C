// This fails for VxWorks RTPs because the initialization of
// __cxa_allocate_exception's emergency buffer mutex will
// itself call malloc(), and will fail if there is no more
// memory available.
// { dg-do run { xfail { { xstormy16-*-* *-*-darwin[3-7]* } || vxworks_rtp } } }
// Copyright (C) 2000, 2002, 2003, 2010, 2012, 2014 Free Software Foundation, Inc.
// Contributed by Nathan Sidwell 6 June 2000 <nathan@codesourcery.com>

// Check we can throw a bad_alloc exception when malloc dies.

typedef __SIZE_TYPE__ size_t;
extern "C" void abort();
extern "C" void *memcpy(void *, const void *, size_t);

// libstdc++ requires a large initialization time allocation for the
// emergency EH allocation pool.  Add that to the arena size.

#if defined(__FreeBSD__) || defined(__sun__) || defined(__hpux__)
// FreeBSD, Solaris and HP-UX require even more space at initialization time.
// FreeBSD 5 now requires over 131072 bytes.
const int arena_size = 262144 + 72 * 1024;
#else
// Because pointers make up the bulk of our exception-initialization
// allocations, we scale by the pointer size from the original
// 32-bit-systems-based estimate.
const int arena_size = 32768 * ((sizeof (void *) + 3)/4) + 72 * 1024;
#endif

struct object
{
  size_t size __attribute__((aligned));
};

static char arena[arena_size] __attribute__((aligned));
static size_t pos;

// So we can force a failure when needed.
static int fail;

extern "C" void *malloc (size_t size)
{
  object *p = reinterpret_cast<object *>(&arena[pos]);

  if (fail)
    return 0;

  p->size = size;
  size = (size + __alignof__(object) - 1) & - __alignof__(object);
  pos += size + sizeof(object);

  // Verify that we didn't run out of memory before getting initialized.
  if (pos > arena_size)
    abort ();

  return p + 1;
}

extern "C" void free (void *)
{
}

extern "C" void *realloc (void *p, size_t size)
{
  void *r;

  if (p)
    {
      object *o = reinterpret_cast<object *>(p) - 1;
      size_t old_size = o->size;

      if (old_size >= size)
	{
	  r = p;
	  o->size = size;
	}
      else
	{
	  r = malloc (size);
	  memcpy (r, p, old_size);
	  free (p);
	}
    }
  else
    r = malloc (size);

  return r;
}

void fn_throw()
#if __cplusplus <= 201402L
throw(int)			// { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } }
#endif
{
  throw 1;
}

void fn_rethrow()
#if __cplusplus <= 201402L
throw(int)			// { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } }
#endif
{
  try{fn_throw();}
  catch(int a){
    throw;}
}

void fn_catchthrow()
#if __cplusplus <= 201402L
throw(int)			// { dg-warning "deprecated" "" { target { c++11 && { ! c++17 } } } }
#endif
{
  try{fn_throw();}
  catch(int a){
    throw a + 1;}
}

int main()
{
  /* On some systems (including FreeBSD and Solaris 2.10),
     __cxa_get_globals will try to call "malloc" when threads are in
     use.  Therefore, we throw one exception up front so that
     __cxa_get_globals is all set up.  Ideally, this would not be
     necessary, but it is a well-known idiom, and using this technique
     means that we can still validate the fact that exceptions can be
     thrown when malloc fails.  */
  try{fn_throw();}
  catch(int a){}

  fail = 1;

  try{fn_throw();}
  catch(int a){}

  try{fn_rethrow();}
  catch(int a){}

  try{fn_catchthrow();}
  catch(int a){}
  
  return 0;
}
