/* PR 11665 
   Orgin: jwhite@cse.unl.edu
   The problem was in initializer_constant_valid_p,
   "for a CONSTRUCTOR, only the last element
   of the CONSTRUCTOR was being checked" 
   (from the email of the patch which fixed this).  
   This used to ICE because GCC thought gdt_table was a 
   constant value when it is not.  */

int x;
struct gdt
{
unsigned a,b,c,d,e,f;
};
void f()
{
struct gdt gdt_table[2]=
{
    {
		0,
		( (((unsigned)(&x))<<(24))&(-1<<(8)) ),
    },
};
}

