// { dg-do assemble  }
// GROUPS passed enums
// friends file
// From: offline!marc@ai.mit.edu (Marc Duponcheel) (Marc Duponcheel)
// Date:     Sat, 6 Feb 93 23:31:22 PST
// Subject:  some 2.2.2 bugs
// Message-ID: <9302070731.AA002jw@offline.UUCP>

class X
{
        enum E { A, B };
static enum E   e;
};
enum X::E X::e = A;
