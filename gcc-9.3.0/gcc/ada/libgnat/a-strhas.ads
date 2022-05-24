------------------------------------------------------------------------------
--                                                                          --
--                         GNAT LIBRARY COMPONENTS                          --
--                                                                          --
--                     A D A . S T R I N G S . H A S H                      --
--                                                                          --
--                                S p e c                                   --
--                                                                          --
-- This specification is derived from the Ada Reference Manual for use with --
-- GNAT.  In accordance with the copyright of that document, you can freely --
-- copy and modify this specification,  provided that if you redistribute a --
-- modified version,  any changes that you have made are clearly indicated. --
--                                                                          --
------------------------------------------------------------------------------

pragma Compiler_Unit_Warning;

with Ada.Containers;

function Ada.Strings.Hash (Key : String) return Containers.Hash_Type;
--  Note: this hash function has predictable collisions and is subject to
--  equivalent substring attacks. It is not suitable for construction of a
--  hash table keyed on possibly malicious user input.

pragma Pure (Ada.Strings.Hash);
