/* { dg-do compile } */ 
/* { dg-options "-O2 -fdump-tree-vrp1-details -fdump-tree-dom2-details -std=gnu89 --param logical-op-non-short-circuit=1" } */
struct bitmap_head_def;
typedef struct bitmap_head_def *bitmap;
typedef const struct bitmap_head_def *const_bitmap;
typedef unsigned long BITMAP_WORD;
typedef struct bitmap_element_def
{
  struct bitmap_element_def *next;
  unsigned int indx;
} bitmap_element;









unsigned char
bitmap_ior_and_compl (bitmap dst, const_bitmap a, const_bitmap b,
		      const_bitmap kill)
{
  unsigned char changed = 0;

  bitmap_element *dst_elt;
  const bitmap_element *a_elt, *b_elt, *kill_elt, *dst_prev;

  while (a_elt || b_elt)
    {
      unsigned char new_element = 0;

      if (b_elt)
	while (kill_elt && kill_elt->indx < b_elt->indx)
	  kill_elt = kill_elt->next;

      if (b_elt && kill_elt && kill_elt->indx == b_elt->indx
	  && (!a_elt || a_elt->indx >= b_elt->indx))
	{
	  bitmap_element tmp_elt;
	  unsigned ix;

	  BITMAP_WORD ior = 0;

	      changed = bitmap_elt_ior (dst, dst_elt, dst_prev,
					a_elt, &tmp_elt, changed);

	}

    }


  return changed;
}
/* The block starting the second conditional has  3 incoming edges,
   we should thread all three, but due to a bug in the threading
   code we missed the edge when the first conditional is false
   (b_elt is zero, which means the second conditional is always
   zero.  VRP1 catches all three.  */
/* { dg-final { scan-tree-dump-times "Threaded" 3 "vrp1" } } */
