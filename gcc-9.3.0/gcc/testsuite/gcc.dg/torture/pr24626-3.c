/* { dg-do compile } */

long fff(int*);
void T(int*);

long F2(int *node)
{
 long call_result = 0;

 if (call_result = fff(node))
  goto error_free_node;

 T(node);
 return 0;

error_free_node:
 T(node);
 return call_result;
}
