-- { dg-do compile }
-- { dg-options "-O -flto -g" { target lto } }

package body Lto15 is

   function Proc (Data : Arr) return R is
   begin
      return (Data'Length, Data);
   end;

end Lto15;
