// { dg-do assemble  }
// GROUPS passed initialization
// init file
// From: thayer@moose.cs.columbia.edu (Charles Thayer)
// Date:     Wed, 30 Sep 92 02:38:17 EDT
// Subject:  small bug
// Message-ID: <9209300638.AA22334@moose.cs.columbia.edu>

int main() {
int offset;
char buf[offset]=""; // { dg-error "6:ISO C\\+\\+ forbids variable length array .buf" } ansi forbids variable arrays
}
