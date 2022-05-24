/* PERMUTE_ARGS:
REQUIRED_ARGS: -dip1000
TEST_OUTPUT:
---
fail_compilation/test16589.d(26): Error: returning `&this.data` escapes a reference to parameter `this`, perhaps annotate with `return`
fail_compilation/test16589.d(31): Error: returning `&this` escapes a reference to parameter `this`, perhaps annotate with `return`
fail_compilation/test16589.d(37): Error: returning `&s.data` escapes a reference to parameter `s`, perhaps annotate with `return`
fail_compilation/test16589.d(42): Error: returning `&s` escapes a reference to parameter `s`, perhaps annotate with `return`
fail_compilation/test16589.d(47): Error: returning `&s.data` escapes a reference to parameter `s`, perhaps annotate with `return`
fail_compilation/test16589.d(52): Error: returning `& s` escapes a reference to parameter `s`, perhaps annotate with `return`
---
*/





// https://issues.dlang.org/show_bug.cgi?id=16589

struct S
{
    int data;

    @safe int* access1()
    {
        return &data;
    }

    @safe S* access2()
    {
        return &this;
    }
}

@safe int* access3(ref S s)
{
    return &s.data;
}

@safe S* access4(ref S s)
{
    return &s;
}

@safe int* access5(S s)
{
    return &s.data;
}

@safe S* access6(S s)
{
    return &s;
}

class C
{
    int data;

    @safe int* access7()
    {
        return &data;
    }
}


