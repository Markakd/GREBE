static void __attribute__((noinline))
bar (void)
{
}

void *
foo (void)
{
  return bar;
}

void
quxx (void)
{
  return bar ();
}
