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

with Ada.Strings.Fixed;
with Interfaces.C;
with Interfaces.C.Strings;
with GNAT.OS_Lib;
with System;

package body Spawn_Manager_Processes is

   package C renames Interfaces.C;
   package CS renames Interfaces.C.Strings;
   package US renames Ada.Strings.Unbounded;

   use type C.int;
   use type CS.chars_ptr;
   use type Interfaces.Integer_64;

   Shell : constant String := "/bin/bash";

   type C_Result is record
      Kind          : C.int;
      Exit_Status   : C.int;
      Signal_Number : C.int;
      Stage         : C.int;
      Error_Number  : C.int;
   end record
     with Convention => C;
   --  C-compatible result record mirrored by struct spawn_posix_result.

   type C_String_Array is array (Natural range <>) of aliased CS.chars_ptr
     with Convention => C;
   --  NUL-terminated argv or envp pointer vector passed to the C boundary.

   function C_Execute
     (Executable          : CS.chars_ptr;
      Arguments           : System.Address;
      Inherit_Environment : C.int;
      Environment         : System.Address;
      Directory           : CS.chars_ptr;
      Stdout_Mode         : C.int;
      Stdout_Path         : CS.chars_ptr;
      Stderr_Mode         : C.int;
      Stderr_Path         : CS.chars_ptr;
      Timeout_MS          : C.long_long;
      Result              : access C_Result)
      return C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_posix_execute";
   --  Invoke the minimal manager-side POSIX execution boundary.

   function Has_Nul (Value : String) return Boolean;
   --  Return True if Value cannot be represented by execve.

   procedure Require_Absolute (Value : String; Name : String);
   --  Reject a non-absolute or non-C-compatible pathname.

   procedure Require_C_String (Value : String; Name : String);
   --  Reject a value which cannot be represented by a C string.

   function To_C_Environment_Mode (Mode : Environment_Mode) return C.int;
   --  Map environment policy to the C boundary's explicit boolean value.

   function To_C_Stream_Mode (Mode : Stream_Mode) return C.int;
   --  Map stream policy without relying on Ada enumeration positions.

   function To_Failure_Stage (Value : C.int) return Failure_Stage;
   --  Map one range-checked C failure-stage value explicitly.

   function To_Termination_Kind (Value : C.int) return Termination_Kind;
   --  Map one range-checked C result-kind value explicitly.

   function Create_Exec_Request
     (Request : Spawn.Protocol.Exec_Request_Type)
      return Execution_Request
   is
      Arguments   : String_Vectors.Vector;
      Environment : Environment_Vectors.Vector;

      function Convert
        (Stream : Spawn.Protocol.Stream_Specification_Type)
         return Stream_Specification;
      --  Map null, truncate and stderr-to-stdout policies to the launch model.

      function Convert
        (Stream : Spawn.Protocol.Stream_Specification_Type)
         return Stream_Specification
      is
      begin
         case Stream.Mode is
            when Spawn.Protocol.Null_Stream =>
               return (Mode => Null_Stream, Path => <>);
            when Spawn.Protocol.Merge_Stdout =>
               return (Mode => Merge_Stdout, Path => <>);
            when Spawn.Protocol.Truncate_File =>
               return
                 (Mode => Truncate_File,
                  Path => Stream.Path);
         end case;
      end Convert;
   begin
      for Argument of Request.Arguments loop
         Arguments.Append (Argument);
      end loop;
      for Item of Request.Environment loop
         Environment.Append
           ((Name  => Item.Name,
             Value => Item.Value));
      end loop;
      return
        (Executable      => Request.Executable,
         Arguments       => Arguments,
         Environment     => Environment,
         Environment_Policy => Replace,
         Directory       => Request.Directory,
         Standard_Output => Convert (Request.Standard_Output),
         Standard_Error  => Convert (Request.Standard_Error),
         Timeout_MS      => Request.Timeout);
   end Create_Exec_Request;

   -------------------------------------------------------------------------

   function Create_Shell_Request
     (Command   : String;
      Directory : String;
      Timeout   : Interfaces.Integer_64)
      return Execution_Request
   is
      Arguments : String_Vectors.Vector;
   begin
      Arguments.Append ("-o");
      Arguments.Append ("pipefail");
      Arguments.Append ("-c");
      Arguments.Append (Command);
      return
        (Executable      => US.To_Unbounded_String (Shell),
         Arguments       => Arguments,
         Environment     => Environment_Vectors.Empty_Vector,
         Environment_Policy => Inherit,
         Directory       => US.To_Unbounded_String (Directory),
         Standard_Output => (Mode => Null_Stream, Path => <>),
         Standard_Error  => (Mode => Null_Stream, Path => <>),
         Timeout_MS      => Timeout);
   end Create_Shell_Request;

   -------------------------------------------------------------------------

   function Diagnostic (Result : Execution_Result) return String
   is
      Error_Text : constant String
        := (if Result.Error_Number = 0 then ""
            else ": " & GNAT.OS_Lib.Errno_Message
              (Err => Integer (Result.Error_Number)));
   begin
      case Result.Kind is
         when Exited =>
            return "exited" & Result.Exit_Status'Image;
         when Signaled =>
            return "signaled" & Result.Signal_Number'Image;
         when Timed_Out =>
            return "timed out";
         when Spawn_Failed =>
            return "spawn failed at " & Result.Stage'Image & Error_Text;
         when Internal_Error =>
            return "internal error at " & Result.Stage'Image & Error_Text;
      end case;
   end Diagnostic;

   -------------------------------------------------------------------------

   function Execute (Request : Execution_Request) return Execution_Result
   is
      Executable_Value : constant String := US.To_String (Request.Executable);
      Directory_Value  : constant String := US.To_String (Request.Directory);
      Argument_Count   : constant Natural
        := Natural (Request.Arguments.Length);
      Environment_Count : constant Natural
        := Natural (Request.Environment.Length);
      C_Arguments : C_String_Array (0 .. Argument_Count + 1)
        := (others => CS.Null_Ptr);
      C_Environment : C_String_Array (0 .. Environment_Count)
        := (others => CS.Null_Ptr);

      Executable  : CS.chars_ptr := CS.Null_Ptr;
      Directory   : CS.chars_ptr := CS.Null_Ptr;
      Stdout_Path : CS.chars_ptr := CS.Null_Ptr;
      Stderr_Path : CS.chars_ptr := CS.Null_Ptr;
      Raw_Result  : aliased C_Result := (others => 0);
      Ignored_Return_Code : C.int;

      procedure Free_Inputs;
      --  Release every C string allocated while translating Request.

      procedure Marshal_Arguments;
      --  Validate and allocate argv entries after the executable at index 0.

      procedure Marshal_Environment;
      --  Validate and allocate the replacement envp entries.

      function Marshal_Stream
        (Stream : Stream_Specification;
         Name   : String)
         return CS.chars_ptr;
      --  Allocate an absolute output path, or return null for /dev/null.

      function To_Result return Execution_Result;
      --  Validate C discriminants and translate the result to Ada.

      procedure Validate_Request;
      --  Validate fields which do not allocate their C representation.

      procedure Free_Inputs
      is
      begin
         for Item of C_Arguments loop
            if Item /= CS.Null_Ptr then
               CS.Free (Item);
            end if;
         end loop;
         for Item of C_Environment loop
            if Item /= CS.Null_Ptr then
               CS.Free (Item);
            end if;
         end loop;
         if Executable /= CS.Null_Ptr then
            CS.Free (Executable);
         end if;
         if Directory /= CS.Null_Ptr then
            CS.Free (Directory);
         end if;
         if Stdout_Path /= CS.Null_Ptr then
            CS.Free (Stdout_Path);
         end if;
         if Stderr_Path /= CS.Null_Ptr then
            CS.Free (Stderr_Path);
         end if;
      end Free_Inputs;

      procedure Marshal_Arguments
      is
      begin
         for Index in 1 .. Argument_Count loop
            declare
               Value : constant String
                 := Request.Arguments.Element (Positive (Index));
            begin
               Require_C_String (Value => Value, Name => "argument");
               C_Arguments (Index) := CS.New_String (Value);
            end;
         end loop;
      end Marshal_Arguments;

      procedure Marshal_Environment
      is
      begin
         for Index in 1 .. Environment_Count loop
            declare
               Item : constant Environment_Entry
                 := Request.Environment.Element (Positive (Index));
               Item_Name  : constant String := US.To_String (Item.Name);
               Item_Value : constant String := US.To_String (Item.Value);
            begin
               Require_C_String
                 (Value => Item_Name,
                  Name  => "environment name");
               Require_C_String
                 (Value => Item_Value,
                  Name  => "environment value");
               if Item_Name'Length = 0
                 or else Ada.Strings.Fixed.Index
                   (Source  => Item_Name,
                    Pattern => "=") /= 0
               then
                  raise Constraint_Error with "invalid environment name";
               end if;
               C_Environment (Index - 1) := CS.New_String
                 (Item_Name & "=" & Item_Value);
            end;
         end loop;
      end Marshal_Environment;

      function Marshal_Stream
        (Stream : Stream_Specification;
         Name   : String)
         return CS.chars_ptr
      is
      begin
         if Stream.Mode /= Truncate_File then
            return CS.Null_Ptr;
         end if;
         declare
            Value : constant String := US.To_String (Stream.Path);
         begin
            Require_Absolute (Value => Value, Name => Name);
            return CS.New_String (Value);
         end;
      end Marshal_Stream;

      function To_Result return Execution_Result
      is
         Kind_Position  : constant Integer := Integer (Raw_Result.Kind);
         Stage_Position : constant Integer := Integer (Raw_Result.Stage);
      begin
         if Kind_Position not in Termination_Kind'Pos (Termination_Kind'First)
           .. Termination_Kind'Pos (Termination_Kind'Last)
           or else Stage_Position not in
             Failure_Stage'Pos (Failure_Stage'First)
             .. Failure_Stage'Pos (Failure_Stage'Last)
           or else Raw_Result.Signal_Number < 0
           or else Raw_Result.Error_Number < 0
         then
            return (Kind => Internal_Error, others => <>);
         end if;
         return
           (Kind          => To_Termination_Kind (Raw_Result.Kind),
            Exit_Status   => Integer (Raw_Result.Exit_Status),
            Signal_Number => Natural (Raw_Result.Signal_Number),
            Stage         => To_Failure_Stage (Raw_Result.Stage),
            Error_Number  => Natural (Raw_Result.Error_Number));
      end To_Result;

      procedure Validate_Request
      is
      begin
         if Request.Standard_Output.Mode = Merge_Stdout then
            raise Constraint_Error with "stdout cannot refer to itself";
         end if;
         Require_Absolute (Value => Executable_Value, Name => "executable");
         if Request.Environment_Policy = Replace then
            Require_Absolute (Value => Directory_Value, Name => "directory");
         else
            --  The compatible shell request historically accepts a relative
            --  directory; the C core interprets it from the manager's cwd.
            Require_C_String (Value => Directory_Value, Name => "directory");
         end if;
         if Request.Timeout_MS < -1 then
            raise Constraint_Error with "timeout must be -1 or nonnegative";
         end if;
         if Request.Environment_Policy = Inherit
           and then not Request.Environment.Is_Empty
         then
            raise Constraint_Error with
              "inherited environment must not contain entries";
         end if;
      end Validate_Request;
   begin
      Validate_Request;

      Executable := CS.New_String (Executable_Value);
      Directory := CS.New_String (Directory_Value);
      C_Arguments (0) := CS.New_String (Executable_Value);
      Marshal_Arguments;
      Marshal_Environment;
      Stdout_Path := Marshal_Stream
        (Stream => Request.Standard_Output,
         Name   => "stdout path");
      Stderr_Path := Marshal_Stream
        (Stream => Request.Standard_Error,
         Name   => "stderr path");

      Ignored_Return_Code := C_Execute
        (Executable          => Executable,
         Arguments           => C_Arguments'Address,
         Inherit_Environment => To_C_Environment_Mode
           (Mode => Request.Environment_Policy),
         Environment         => C_Environment'Address,
         Directory           => Directory,
         Stdout_Mode         => To_C_Stream_Mode
           (Mode => Request.Standard_Output.Mode),
         Stdout_Path         => Stdout_Path,
         Stderr_Mode         => To_C_Stream_Mode
           (Mode => Request.Standard_Error.Mode),
         Stderr_Path         => Stderr_Path,
         Timeout_MS          => C.long_long (Request.Timeout_MS),
         Result              => Raw_Result'Access);
      --  The C return value only distinguishes its Internal_Error variant;
      --  Raw_Result remains the single detailed result translated below.
      pragma Unreferenced (Ignored_Return_Code);

      Free_Inputs;
      return To_Result;

   exception
      when others =>
         Free_Inputs;
         raise;
   end Execute;

   -------------------------------------------------------------------------

   function Has_Nul (Value : String) return Boolean
   is (Ada.Strings.Fixed.Index (Source => Value, Pattern => (1 => ASCII.NUL))
       /= 0);

   -------------------------------------------------------------------------

   procedure Require_Absolute (Value : String; Name : String)
   is
   begin
      Require_C_String (Value => Value, Name => Name);
      if Value'Length = 0 or else Value (Value'First) /= '/' then
         raise Constraint_Error with Name & " must be absolute";
      end if;
   end Require_Absolute;

   -------------------------------------------------------------------------

   procedure Require_C_String (Value : String; Name : String)
   is
   begin
      if Has_Nul (Value) then
         raise Constraint_Error with Name & " contains NUL";
      end if;
   end Require_C_String;

   -------------------------------------------------------------------------

   function To_C_Environment_Mode (Mode : Environment_Mode) return C.int
   is
   begin
      case Mode is
         when Replace => return 0;
         when Inherit => return 1;
      end case;
   end To_C_Environment_Mode;

   -------------------------------------------------------------------------

   function To_C_Stream_Mode (Mode : Stream_Mode) return C.int
   is
   begin
      case Mode is
         when Null_Stream   => return 0;
         when Truncate_File => return 1;
         when Merge_Stdout  => return 2;
      end case;
   end To_C_Stream_Mode;

   -------------------------------------------------------------------------

   function To_Failure_Stage (Value : C.int) return Failure_Stage
   is
   begin
      case Value is
         when 0  => return No_Failure;
         when 1  => return Enable_Subreaper;
         when 2  => return Create_Error_Pipe;
         when 3  => return Fork_Child;
         when 4  => return Process_Group;
         when 5  => return Parent_Death;
         when 6  => return Open_Stdin;
         when 7  => return Open_Stdout;
         when 8  => return Open_Stderr;
         when 9  => return Duplicate_Stdin;
         when 10 => return Duplicate_Stdout;
         when 11 => return Duplicate_Stderr;
         when 12 => return Change_Directory;
         when 13 => return Reset_Signals;
         when 14 => return Close_Descriptors;
         when 15 => return Exec_Target;
         when 16 => return Wait_Child;
         when 17 => return Terminate_Group;
         when others =>
            raise Program_Error with "invalid C failure stage";
      end case;
   end To_Failure_Stage;

   -------------------------------------------------------------------------

   function To_Termination_Kind (Value : C.int) return Termination_Kind
   is
   begin
      case Value is
         when 0 => return Exited;
         when 1 => return Signaled;
         when 2 => return Timed_Out;
         when 3 => return Spawn_Failed;
         when 4 => return Internal_Error;
         when others =>
            raise Program_Error with "invalid C termination kind";
      end case;
   end To_Termination_Kind;

end Spawn_Manager_Processes;
