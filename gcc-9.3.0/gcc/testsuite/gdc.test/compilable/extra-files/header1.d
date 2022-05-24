module foo.bar;

import core.vararg;
import std.stdio;

pragma(lib, "test");
pragma(msg, "Hello World");

static assert(true, "message");

alias double mydbl;

int testmain()
in
{
    assert(1+(2+3) == -(1 - 2*3));
}
out (result)
{
    assert(result == 0);
}
body
{
    float f = float.infinity;
    int i = cast(int) f;
    writeln((i,1),2);
    writeln(cast(int)float.max);
    assert(i == cast(int)float.max);
    assert(i == 0x80000000);
    return 0;
}

struct S { int m, n; }

template Foo(T, int V)
{
    void foo(...)
    {
        static if (is(Object _ : X!TL, alias X, TL...)) {}  // Bugzilla 10044

        auto x = __traits(hasMember, Object, "noMember");
        auto y = is(Object : X!TL, alias X, TL...);
        assert(!x && !y, "message");

        S s = { 1,2 };
        auto a = [1, 2, 3];
        auto aa = [1:1, 2:2, 3:3];

        int n,m;
    }

    int bar(double d, int x)
    {
    if (d)
    {   d++;
    }
    else
        d--;

    asm
    {	naked ;
        mov EAX, 3;
    }

    for (;;)
    {
        d = d + 1;
    }

    for (int i = 0; i < 10; i++)
    {
        d = i ? d + 1 : 5;
    }

    char[] s;
    foreach (char c; s)
    {
        d *= 2;
        if (d)
        break;
        else
        continue;
    }

    switch (V)
    {
        case 1:
        case 2: break;
        case 3: goto case 1;
        case 4: goto default;
        default:
        d /= 8;
        break;
    }

        enum Label { A, B, C }
        void fswitch(Label l)
        {
            final switch (l)
            {
            case A: break;
            case B: break;
            case C: break;
            }
        }

    loop:
    while (x)
    {
        x--;
        if (x)
        break loop;
        else
        continue loop;
    }

    do
    {
        x++;
    } while (x < 10);

    try
    {
        bar(1, 2);
    }
    catch (Object o)
    {
        x++;
    }
    finally
    {
        x--;
    }

    try
	    bar(1, 2);
    catch(Object o)
	    x++;
    finally
	    x--;

    Object o;
    synchronized (o)
    {
        x = ~x;
    }

    synchronized
    {
        x = x < 3;
    }

    with (o)
    {
        toString();
    }
    }
}

static this()
{
}

static ~this()
{
}

pure nothrow @safe @nogc static  this() {}
pure nothrow @safe @nogc static ~this() {}
static  this() pure nothrow @safe @nogc {}
static ~this() pure nothrow @safe @nogc {}

pure nothrow @safe @nogc shared static  this() {}
pure nothrow @safe @nogc shared static ~this() {}
shared static  this() pure nothrow @safe @nogc {}
shared static ~this() pure nothrow @safe @nogc {}

interface iFoo{}
class xFoo: iFoo{}

interface iFoo2{}
class xFoo2: iFoo, iFoo2{}

class Foo3
{
    this(int a, ...){}
    this(int* a){}
}

alias int myint;

static notquit = 1;

class Test
{
    void a() {}
    void b() {}
    void c() {}
    void d() {}
    void e() {}
    void f() {}
    void g() {}
    void h() {}
    void i() {}
    void j() {}
    void k() {}
    void l() {}
    void m() {}
    void n() {}
    void o() {}
    void p() {}
    void q() {}
    void r() {}
    void s() {}
    void t() {}
    void u() {}
    void v() {}
    void w() {}
    void x() {}
    void y() {}
    void z() {}

    void aa() {}
    void bb() {}
    void cc() {}
    void dd() {}
    void ee() {} // Try adding or removing some functions here to see the effect.

    template A(T) { }

    alias A!(uint) getHUint;
    alias A!(int) getHInt;
    alias A!(float) getHFloat;
    alias A!(ulong) getHUlong;
    alias A!(long) getHLong;
    alias A!(double) getHDouble;
    alias A!(byte) getHByte;
    alias A!(ubyte) getHUbyte;
    alias A!(short) getHShort;
    alias A!(ushort) getHUShort;
    alias A!(real) getHReal;

    alias void F();

    pure nothrow @safe @nogc unittest {}
    pure nothrow @safe @nogc invariant {}

    pure nothrow @safe @nogc new (size_t sz) { return null; }
    pure nothrow @safe @nogc delete (void* p) { }
}

template templ( T )
{
    void templ( T val )
    {
        pragma( msg, "Invalid destination type." );
    }
}

static char[] charArray = [ '\"', '\'' ];

class Point
{
    auto x = 10;
    uint y = 20;
}

template Foo2(bool bar)
{
    void test()
    {
    static if(bar)
    {
        int i;
    }
    else
    {
    }
    static if(!bar)
    {
    }
    else
    {
    }
    }
}


template Foo4()
{
        void bar()
        {
        }
}

template Foo4x( T... ) {}

class Baz4
{
        mixin Foo4 foo;
        mixin Foo4x!(int, "str") foox;

        alias foo.bar baz;
}

int test(T)(T t)
{
        if (auto o = cast(Object)t) return 1;
        return 0;
}

enum x6 = 1;

bool foo6(int a, int b, int c, int d)
{
    return (a < b) != (c < d);
}

auto foo7(int x)
{
        return 5;
}

class D8{}
void func8()
{
  scope a= new D8();
}

T func9(T)() if (true)
{
    T i;
    scope(exit) i= 1;
    scope(success) i = 2;
    scope(failure) i = 3;
    return i;
}

template V10(T)
{
    void func()
    {
        for(int i,j=4; i<3;i++)
        {
        }
    }
}

int foo11(int function() fn)
{
    return fn();
}

int bar11(T)()
{
    return foo11(function int (){ return 0; });
}


struct S6360
{
    @property long weeks1() const pure nothrow { return 0; }

    @property const pure nothrow long weeks2() { return 0; }
}


struct S12
{
    /// postfix storage class and constructor
    this(int n) nothrow{}

    /// prefix storage class (==StorageClassDeclaration) and constructor
    nothrow this(string s){}
}

/// dummy
struct T12
{
    /// postfix storage class and template constructor
    this()(int args) immutable { }

    /// prefix storage class (==StorageClassDeclaration) and template constructor
    immutable this(A...)(A args){ }
}


// 6591
import std.stdio : writeln, F = File;

void foo6591()()
{
    import std.stdio : writeln, F = File;
}


// 8081
version(unittest) {
    pure nothrow unittest {}
    pure nothrow unittest {}

    public unittest {}
    extern(C) unittest {}
    align unittest {}
}


// 10334

template Foo10334(T) if (Bar10334!()) {}                ///
template Foo10334(T) if (Bar10334!100) {}               ///
template Foo10334(T) if (Bar10334!3.14) {}              ///
template Foo10334(T) if (Bar10334!"str") {}             ///
template Foo10334(T) if (Bar10334!1.4i) {}              ///
template Foo10334(T) if (Bar10334!null) {}              ///
template Foo10334(T) if (Bar10334!true) {}              ///
template Foo10334(T) if (Bar10334!false) {}             ///
template Foo10334(T) if (Bar10334!'A') {}               ///
template Foo10334(T) if (Bar10334!int) {}               ///
template Foo10334(T) if (Bar10334!string) {}            ///
template Foo10334(T) if (Bar10334!wstring) {}           ///
template Foo10334(T) if (Bar10334!dstring) {}           ///
template Foo10334(T) if (Bar10334!this) {}              ///
template Foo10334(T) if (Bar10334!([1,2,3])) {}         ///
template Foo10334(T) if (Bar10334!(Baz10334!())) {}     ///
template Foo10334(T) if (Bar10334!(Baz10334!T)) {}      ///
template Foo10334(T) if (Bar10334!(Baz10334!100)) {}    ///
template Foo10334(T) if (Bar10334!(.foo)) {}            ///
template Foo10334(T) if (Bar10334!(const int)) {}       ///
template Foo10334(T) if (Bar10334!(shared T)) {}        ///

template Test10334(T...) {}     ///
mixin Test10334!int a;          ///
mixin Test10334!(int,long) b;   ///
mixin Test10334!"str" c;        ///

// 12266
auto clamp12266a(T1, T2, T3)(T1 x, T2 min_val, T3 max_val)
{
    return 0;
}
pure clamp12266b(T1, T2, T3)(T1 x, T2 min_val, T3 max_val)
{
    return 0;
}
@disable pure clamp12266c(T1, T2, T3)(T1 x, T2 min_val, T3 max_val)
{
    return 0;
}

// 13832
alias Dg13832 = ref int delegate();

// 16590
class TestClass {
    int aa;
    int b1, b2;
    this(int b1, int b2)
    {
        this.b1 = b1;
        this.b2 = b2;
    }

    ref foo() {
        return aa;
    }

    ref retFunc() return {
        return aa;
    }

    ~this() @trusted @disable @nogc {
    }
}

class FooA {
    protected void method42() {

    }

    ~this() @safe {
    }

}


class Bar : FooA {
    override void method42() {

   }
}

double foo() @trusted {
    int a = 5;
    return a;
}

struct Foo1(size_t Size = 42 / magic()) {

}


size_t magic() {
    return 42;
}

class Foo2A {

    immutable(FooA) Dummy = new immutable(FooA);
    private immutable pure nothrow @nogc @safe this() {

    }

}

// bugzilla 15676
struct Foo3A(T)
{
    @disable this(this);
    @disable this();
}
