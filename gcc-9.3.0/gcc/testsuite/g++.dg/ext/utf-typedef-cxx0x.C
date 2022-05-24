/* Contributed by Kris Van Hees <kris.van.hees@oracle.com> */
/* Ensure that a typedef to char16_t/char32_t issues an error in c++0x. */
/* { dg-do compile { target c++11 } } */

typedef short unsigned int	char16_t; /* { dg-error "redeclaration" } */
typedef unsigned int		char32_t; /* { dg-error "redeclaration" } */
