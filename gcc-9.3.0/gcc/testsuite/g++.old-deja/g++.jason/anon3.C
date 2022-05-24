// { dg-do assemble  }
// Bug: g++ dies.

class cl {
public:
  cl();
  void set(void *, char *, int);
private:
  union {
    float vf;
    struct ff { // { dg-error "" } nested class in anonymous union
      void *ptr;
      char *name;
      int sz;
    } *vff;
  };
};

void cl::set(void *p, char *n, int sz)
{
    vff = new ff; // This procude an internal compiler error.
    vff->ptr = p;
    vff->name = n;
    vff->sz = sz;
}
