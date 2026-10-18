--
--  Process Spawn Manager
--
--  Copyright (C) 2026 secunet Security Networks AG
--
--  This program is free software; you can redistribute it and/or
--  modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation; either version 2
--  of the License, or (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
--  General Public License for more details.
--
--  As a special exception, if other files instantiate generics from this
--  unit, or you link this unit with other files to produce an executable,
--  this unit does not by itself cause the resulting executable to be covered
--  by the GNU General Public License. This exception does not invalidate any
--  other reason why the executable might be covered by the GNU Public
--  License.
--

with Ada.Containers.Indefinite_Vectors;
with Ada.Containers.Vectors;
with Ada.Strings.Unbounded;
with Interfaces;

with Spawn.Protocol;

package Spawn_Manager_Processes is

   --  This package is the typed Ada side of the single POSIX execution
   --  boundary. It normalizes both wire request variants, validates every
   --  value which will cross into C and translates the result back without
   --  exposing C representation choices to the manager loop.

   package String_Vectors is new Ada.Containers.Indefinite_Vectors
     (Index_Type   => Positive,
      Element_Type => String);

   type Environment_Entry is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Value : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   package Environment_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Positive,
      Element_Type => Environment_Entry);

   type Environment_Mode is (Inherit, Replace);
   --  Shell requests inherit the immutable manager environment; structured
   --  requests replace it completely, including with an empty vector.

   type Stream_Mode is (Null_Stream, Truncate_File, Merge_Stdout);
   --  Stderr may duplicate stdout; other modes select null or truncate output.

   type Stream_Specification is record
      Mode : Stream_Mode := Null_Stream;
      Path : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Execution_Request is record
      Executable      : Ada.Strings.Unbounded.Unbounded_String;
      Arguments       : String_Vectors.Vector;
      Environment     : Environment_Vectors.Vector;
      Environment_Policy : Environment_Mode := Replace;
      Directory       : Ada.Strings.Unbounded.Unbounded_String;
      Standard_Output : Stream_Specification;
      Standard_Error  : Stream_Specification;
      Timeout_MS      : Interfaces.Integer_64 := Interfaces.Integer_64 (-1);
   end record;
   --  Fully normalized launch data consumed by the single POSIX boundary.

   type Termination_Kind is
     (Exited,
      Signaled,
      Timed_Out,
      Spawn_Failed,
      Internal_Error);

   type Failure_Stage is
     (No_Failure,
      Enable_Subreaper,
      Create_Error_Pipe,
      Fork_Child,
      Process_Group,
      Parent_Death,
      Open_Stdin,
      Open_Stdout,
      Open_Stderr,
      Duplicate_Stdin,
      Duplicate_Stdout,
      Duplicate_Stderr,
      Change_Directory,
      Reset_Signals,
      Close_Descriptors,
      Exec_Target,
      Wait_Child,
      Terminate_Group);

   type Execution_Result is record
      Kind          : Termination_Kind := Internal_Error;
      Exit_Status   : Integer := -1;
      Signal_Number : Natural := 0;
      Stage         : Failure_Stage := No_Failure;
      Error_Number  : Natural := 0;
   end record;
   --  Complete C-boundary result before conversion to the wire alternatives.

   function Create_Shell_Request
     (Command   : String;
      Directory : String;
      Timeout   : Interfaces.Integer_64)
      return Execution_Request;
   --  Normalize one compatible shell command to the common launch model.

   function Create_Exec_Request
     (Request : Spawn.Protocol.Exec_Request_Type)
      return Execution_Request;
   --  Normalize one structured request to the common launch model.

   function Diagnostic (Result : Execution_Result) return String;
   --  Return a request-data-free diagnostic for manager debug logging.

   function Execute (Request : Execution_Request) return Execution_Result;
   --  Validate and execute one immutable request through the POSIX core.

end Spawn_Manager_Processes;
