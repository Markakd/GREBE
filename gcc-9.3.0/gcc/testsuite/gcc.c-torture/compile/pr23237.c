/* Don't assemble, as this section syntax may not be valid on all platforms
   (e.g., Darwin).  */
/* { dg-do compile } */

/* { dg-require-effective-target named_sections } */

static __attribute__ ((__section__ (".init.data"))) char *message;
static __attribute__ ((__section__ (".init.data"))) int (*actions[])(void) = {};
void unpack_to_rootfs(void)
{
  while (!message)
  {
    if(!actions[0])
      return;
  }
}
