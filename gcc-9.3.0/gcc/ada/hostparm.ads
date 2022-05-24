------------------------------------------------------------------------------
--                                                                          --
--                         GNAT COMPILER COMPONENTS                         --
--                                                                          --
--                             H O S T P A R M                              --
--                                                                          --
--                                 S p e c                                  --
--                                                                          --
--          Copyright (C) 1992-2019, Free Software Foundation, Inc.         --
--                                                                          --
-- GNAT is free software;  you can  redistribute it  and/or modify it under --
-- terms of the  GNU General Public License as published  by the Free Soft- --
-- ware  Foundation;  either version 3,  or (at your option) any later ver- --
-- sion.  GNAT is distributed in the hope that it will be useful, but WITH- --
-- OUT ANY WARRANTY;  without even the  implied warranty of MERCHANTABILITY --
-- or FITNESS FOR A PARTICULAR PURPOSE.                                     --
--                                                                          --
-- As a special exception under Section 7 of GPL version 3, you are granted --
-- additional permissions described in the GCC Runtime Library Exception,   --
-- version 3.1, as published by the Free Software Foundation.               --
--                                                                          --
-- You should have received a copy of the GNU General Public License and    --
-- a copy of the GCC Runtime Library Exception along with this program;     --
-- see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see    --
-- <http://www.gnu.org/licenses/>.                                          --
--                                                                          --
-- GNAT was originally developed  by the GNAT team at  New York University. --
-- Extensive contributions were provided by Ada Core Technologies Inc.      --
--                                                                          --
------------------------------------------------------------------------------

--  This package defines some system dependent parameters for GNAT. These
--  are parameters that are relevant to the host machine on which the
--  compiler is running, and thus this package is part of the compiler.

with Types;

package Hostparm is

   ---------------------
   -- HOST Parameters --
   ---------------------

   Direct_Separator : constant Character;
   pragma Import (C, Direct_Separator, "__gnat_dir_separator");
   Normalized_CWD : constant String := "." & Direct_Separator;
   --  Normalized string to access current directory

   Max_Line_Length : constant :=
     Types.Column_Number'Pred (Types.Column_Number'Last);
   --  Maximum source line length. By default we set it to the maximum
   --  value that can be supported, which is given by the range of the
   --  Column_Number type. We subtract 1 because need to be able to
   --  have a valid Column_Number equal to Max_Line_Length to represent
   --  the location of a "line too long" error.
   --
   --  200 is the minimum value required (RM 2.2(15)). The value set here
   --  can be reduced by the explicit use of the -gnatyM style switch.

   Max_Name_Length : constant := 1024;
   --  Maximum length of unit name (including all dots, and " (spec)") and
   --  of file names in the library, must be at least Max_Line_Length, but
   --  can be larger.

   Tag_Errors : constant Boolean := False;
   --  If set to true, then brief form error messages will be prefaced by
   --  the string "error:". Used as default for Opt.Unique_Error_Tag.

   Exclude_Missing_Objects : constant Boolean := True;
   --  If set to true, gnatbind will exclude from consideration all
   --  non-existent .o files.

end Hostparm;
