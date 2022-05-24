/*
TEST_OUTPUT:
---
fail_compilation/fail109.d(12): Error: enum member fail109.Bool.Unknown initialization with `Bool.True+1` causes overflow for type `bool`
---
*/

enum Bool : bool
{
    False,
    True,
    Unknown
}

/* Bugzilla 11088
TEST_OUTPUT:
---
fail_compilation/fail109.d(25): Error: enum member fail109.E.B initialization with `E.A+1` causes overflow for type `int`
fail_compilation/fail109.d(31): Error: enum member fail109.E1.B initialization with `E1.A+1` causes overflow for type `short`
---
*/
enum E
{
    A = int.max,
    B
}

enum E1 : short
{
    A = short.max,
    B
}

/* Bugzilla 14950
TEST_OUTPUT:
---
fail_compilation/fail109.d(50): Deprecation: Comparison between different enumeration types `B` and `C`; If this behavior is intended consider using `std.conv.asOriginalType`
fail_compilation/fail109.d(50): Error: enum member fail109.B.end initialization with `B.start+1` causes overflow for type `C`
---
*/
enum C
{
    start,
    end
}

enum B
{
    start = C.end,
    end
}

/* Bugzilla 11849
TEST_OUTPUT:
---
fail_compilation/fail109.d(72): Error: enum fail109.RegValueType1a recursive definition of `.max` property
fail_compilation/fail109.d(79): Error: enum fail109.RegValueType1b recursive definition of `.max` property
fail_compilation/fail109.d(84): Error: enum fail109.RegValueType2a recursive definition of `.min` property
fail_compilation/fail109.d(91): Error: enum fail109.RegValueType2b recursive definition of `.min` property
---
*/

alias DWORD = uint;

enum : DWORD
{
    REG_DWORD = 4
}

enum RegValueType1a : DWORD
{
    Unknown = DWORD.max,
    DWORD = REG_DWORD,
}

enum RegValueType1b : DWORD
{
    DWORD = REG_DWORD,
    Unknown = DWORD.max,
}

enum RegValueType2a : DWORD
{
    Unknown = DWORD.min,
    DWORD = REG_DWORD,
}

enum RegValueType2b : DWORD
{
    DWORD = REG_DWORD,
    Unknown = DWORD.min,
}
