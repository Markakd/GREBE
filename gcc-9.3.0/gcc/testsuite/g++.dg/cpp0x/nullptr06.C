// { dg-do compile { target c++11 } }

// Test compare to pointer

#define assert_true(b) do { char c[2 * bool(b) - 1]; } while(0)

constexpr char* cp1 = nullptr;

void fun()
{
  assert_true(cp1 == nullptr);
  decltype(nullptr) mynull = 0;
  assert_true(cp1 == mynull);
}
