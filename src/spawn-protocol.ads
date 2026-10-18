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
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;

package Spawn.Protocol is

   --  Version 2 wire format
   --
   --  All offsets below are zero-based byte offsets. Integers are unsigned
   --  big-endian unless marked i64. Lengths count payload bytes, not Ada
   --  characters, and strings contain their bytes verbatim. NUL is forbidden.
   --
   --    Common frame header (12 bytes)
   --
   --      0  u8[4]  magic "SPWN"
   --      4  u16    protocol version, fixed value 2
   --      6  u16    message kind: 1 shell, 2 exec, 3 result
   --      8  u32    payload length, excluding this header
   --
   --    Reusable fields
   --
   --      string  := u32 byte_length, u8[byte_length]
   --      vector  := u32 element_count, element[element_count]
   --      stream  := u8 mode, where 0 is /dev/null and 1 is followed by
   --                 one absolute-path string opened with truncate semantics
   --                 Mode 2 has no path and duplicates stdout for stderr;
   --                 it is never legal in the stdout position.
   --      timeout := i64 two's-complement milliseconds; -1 means unlimited
   --
   --    Shell request payload (message kind 1)
   --
   --      string command
   --      string working_directory
   --      i64    timeout
   --
   --    The shell request inherits the manager environment. The manager maps
   --    it to absolute `/bin/bash -o pipefail -c command`; stdin, stdout and
   --    stderr use /dev/null unless redirection is part of command itself.
   --
   --    Exec request payload (message kind 2)
   --
   --      string executable                 absolute; becomes argv[0]
   --      u32    argument_count
   --      string argument[argument_count]   excludes argv[0]
   --      u32    environment_count
   --      repeat environment_count times:
   --         string environment_name
   --         string environment_value
   --      string working_directory
   --      stream stdout
   --      stream stderr
   --      i64    timeout
   --
   --    Exec requests replace the complete environment; a zero count means
   --    an empty environment. Standard input remains /dev/null in version 2.
   --
   --    Result payload (message kind 3)
   --
   --      u8 result_kind, followed by exactly one alternative:
   --        0 exited:           u32 exit_status
   --        1 signaled:         u16 signal_number
   --        2 timed_out:        no additional bytes
   --        3 spawn_failed:     u16 stage, u32 errno, diagnostic
   --        4 request_rejected: diagnostic
   --        5 protocol_failed:  diagnostic
   --
   --      diagnostic := u32 byte_length, u8[byte_length]
   --
   --    Spawn-failure stages use values 0 through 17 in Failure_Stage order.
   --    Every frame is exact: trailing bytes, unknown values, an inconsistent
   --    payload length or a field outside the limits below are rejected.

   Magic_Size              : constant := 4;
   U16_Size                : constant := 2;
   U32_Size                : constant := 4;
   I64_Size                : constant := 8;
   Stream_Mode_Size        : constant := 1;
   Result_Kind_Size        : constant := 1;

   Header_Magic_Offset     : constant := 0;
   Header_Version_Offset   : constant := Header_Magic_Offset + Magic_Size;
   Header_Kind_Offset      : constant := Header_Version_Offset + U16_Size;
   Header_Length_Offset    : constant := Header_Kind_Offset + U16_Size;
   Header_Size             : constant := Header_Length_Offset + U32_Size;
   Minimum_Shell_Command_Size : constant := 2;
   Minimum_Shell_Request_Frame_Size : constant
     := Header_Size + 2 * U32_Size + I64_Size
        + Minimum_Shell_Command_Size;

   Protocol_Magic : constant Ada.Streams.Stream_Element_Array (1 .. Magic_Size)
     := (Character'Pos ('S'),
         Character'Pos ('P'),
         Character'Pos ('W'),
         Character'Pos ('N'));
   Protocol_Version        : constant Interfaces.Unsigned_16 := 2;

   Maximum_Frame_Size      : constant := 128 * 1024;
   Maximum_String_Size     : constant := 64 * 1024;
   Maximum_Vector_Length   : constant := 1024;
   Maximum_Diagnostic_Size : constant := 4 * 1024;

   type Message_Kind is (Shell_Request, Exec_Request, Result_Message);
   --  Header values are assigned explicitly as 1, 2 and 3 by the encoder.

   type Header_Type is record
      Kind           : Message_Kind;
      Payload_Length : Interfaces.Unsigned_32;
   end record;

   subtype Timeout_Milliseconds is Interfaces.Integer_64
     range Interfaces.Integer_64 (-1) .. Interfaces.Integer_64'Last;

   type Shell_Request_Type is record
      Command   : Ada.Strings.Unbounded.Unbounded_String;
      Directory : Ada.Strings.Unbounded.Unbounded_String;
      Timeout   : Timeout_Milliseconds;
   end record;

   package String_Vectors is new Ada.Containers.Indefinite_Vectors
     (Index_Type   => Positive,
      Element_Type => String);

   type Environment_Entry_Type is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Value : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   package Environment_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Positive,
      Element_Type => Environment_Entry_Type);

   type Stream_Mode is (Null_Stream, Truncate_File, Merge_Stdout);
   --  Wire values are the zero-based positions fixed in the format above.

   type Stream_Specification_Type
     (Mode : Stream_Mode := Null_Stream)
   is record
      case Mode is
         when Null_Stream | Merge_Stdout =>
            null;
         when Truncate_File =>
            Path : Ada.Strings.Unbounded.Unbounded_String;
      end case;
   end record;

   type Exec_Request_Type is record
      Executable      : Ada.Strings.Unbounded.Unbounded_String;
      Arguments       : String_Vectors.Vector;
      Environment     : Environment_Vectors.Vector;
      Directory       : Ada.Strings.Unbounded.Unbounded_String;
      Standard_Output : Stream_Specification_Type;
      Standard_Error  : Stream_Specification_Type;
      Timeout         : Timeout_Milliseconds;
   end record;

   type Result_Kind is
     (Exited,
      Signaled,
      Timed_Out,
      Spawn_Failed,
      Request_Rejected,
      Protocol_Failed);
   --  Wire values are the zero-based positions fixed in the format above.

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
   --  Wire values 0 through 17 follow this fixed order.

   type Failure_Details is record
      Stage        : Failure_Stage := No_Failure;
      Error_Number : Interfaces.Unsigned_32 := 0;
      Diagnostic   : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Result_Type (Kind : Result_Kind := Protocol_Failed) is record
      case Kind is
         when Exited =>
            Exit_Status : Interfaces.Unsigned_32 := 0;
         when Signaled =>
            Signal_Number : Interfaces.Unsigned_16 := 0;
         when Timed_Out =>
            null;
         when Spawn_Failed =>
            Failure : Failure_Details;
         when Request_Rejected | Protocol_Failed =>
            Diagnostic : Ada.Strings.Unbounded.Unbounded_String;
      end case;
   end record;

   procedure Decode_Header
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Header       : out Header_Type);
   --  Decode and validate one complete fixed header against Active_Bound.

   procedure Decode_Exec_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Exec_Request_Type);
   --  Decode one exact exec-request frame without accepting trailing bytes.

   procedure Decode_Result
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Result       : out Result_Type);
   --  Decode one exact result frame without accepting trailing bytes.

   procedure Decode_Shell_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Shell_Request_Type);
   --  Decode one exact shell-request frame without accepting trailing bytes.

   procedure Encode_Header
     (Header :     Header_Type;
      Data   : in out Ada.Streams.Stream_Element_Array);
   --  Encode Header into the first Header_Size bytes of Data.

   procedure Encode_Exec_Request
     (Request      :     Exec_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array);
   --  Encode one exec request into an exactly sized bounded Data array.

   procedure Encode_Result
     (Result       :     Result_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array);
   --  Encode one result into an exactly sized bounded Data array.

   procedure Encode_Shell_Request
     (Request      :     Shell_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array);
   --  Encode one shell request into an exactly sized bounded Data array.

   function Frame_Length
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive)
      return Positive;
   --  Return the complete bounded frame length or raise Protocol_Error.

   function Exec_Request_Frame_Length
     (Request      : Exec_Request_Type;
      Active_Bound : Positive)
      return Positive;
   --  Return the exact encoded exec-request frame length.

   function Result_Frame_Length
     (Result       : Result_Type;
      Active_Bound : Positive)
      return Positive;
   --  Return the exact encoded result frame length.

   function Shell_Request_Frame_Length
     (Request      : Shell_Request_Type;
      Active_Bound : Positive)
      return Positive;
   --  Return the exact encoded shell-request frame length.

   procedure Validate_Active_Bound (Active_Bound : Positive);
   --  Reject an active frame bound outside Header_Size .. Maximum_Frame_Size.

   Protocol_Error : exception;
   Request_Error  : exception;

end Spawn.Protocol;
