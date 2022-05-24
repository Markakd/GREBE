/*
TEST_OUTPUT:
---
fail_compilation/lookup.d(23): Error: no property 'X' for type 'lookup.B'
fail_compilation/lookup.d(23):        while evaluating: `static assert((B).X == 0)`
fail_compilation/lookup.d(24): Error: no property 'Y' for type 'lookup.B'
fail_compilation/lookup.d(24):        while evaluating: `static assert((B).Y == 2)`
---
*/

import imports.imp1;

enum X = 0;

class B
{
    import imports.imp2;
    static assert(X == 0);
    static assert(Y == 2);
}
class C : B
{
    static assert(B.X == 0);
    static assert(B.Y == 2);

    static assert(X == 0);
    static assert(Y == 1);
}
