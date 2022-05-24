with Ada.Tags.Generic_Dispatching_Constructor;

package Generic_Disp_Pkg is
   type Iface is interface;
   function Constructor (I : not null access Integer) return Iface is abstract;
   function Dispatching_Constructor
      is new Ada.Tags.Generic_Dispatching_Constructor
               (T           => Iface,
                Parameters  => Integer,
                Constructor => Constructor);
   type DT is new Iface with null record; 
   overriding
   function Constructor (I : not null access Integer) return DT;
end Generic_Disp_Pkg;
