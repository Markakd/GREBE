// { dg-do assemble  }
// GROUPS passed arm
int a, b;

// declaring an array of references should be illegal
int & v[ 2] = { a, b};  // { dg-error "7:declaration of .v. as array of references" }
