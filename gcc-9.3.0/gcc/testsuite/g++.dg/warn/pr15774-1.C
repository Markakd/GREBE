// { dg-do compile { target { { i?86-*-* x86_64-*-* } && ia32 } } }
// Test that an new declartion with different attributes then old one fail.
extern void foo (int); // { dg-message "old declaration" }

void
bar (void)
{
  foo (1);
}

void __attribute__((stdcall)) foo (int i) // { dg-error "new declaration" }
{
}


