// { dg-do assemble  }
// GROUPS passed initialization
int main( int argc, char**argv, char** envp ){
    char* domain = argv[1];
    domain = domain? (char*)"component" : domain;
}
