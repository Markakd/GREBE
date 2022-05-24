// { dg-do assemble  }
// { dg-options "-W -Wall" }

typedef unsigned long size_t;
extern void* malloc (size_t);
extern void free (void*);
extern void* realloc (void*, size_t);

struct vtable {
  void* (* _malloc) (size_t);
  void (* _free) (void*);
  void* (* _realloc) (void*, size_t);
};

struct vtable mtable = { malloc, free };  // { dg-warning "" } _realloc
