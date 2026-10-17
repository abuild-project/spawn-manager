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

with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;

package body Spawn.Protocol.Tests is

   use Ahven;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;

   procedure Exec_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 62)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#32#,
            16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#61#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#45#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#56#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#00#,
            16#01#, 16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#65#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Expected : Exec_Request_Type;
      Data     : Ada.Streams.Stream_Element_Array (Golden'Range);
      Decoded  : Exec_Request_Type;
   begin
      Expected.Executable := Ada.Strings.Unbounded.To_Unbounded_String ("/x");
      Expected.Arguments.Append ("a");
      Expected.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String ("V")));
      Expected.Directory := Ada.Strings.Unbounded.To_Unbounded_String ("/");
      Expected.Standard_Output := (Mode => Null_Stream);
      Expected.Standard_Error :=
        (Mode => Truncate_File,
         Path => Ada.Strings.Unbounded.To_Unbounded_String ("/e"));
      Expected.Timeout := -1;

      Assert
        (Condition => Exec_Request_Frame_Length
           (Request      => Expected,
            Active_Bound => Maximum_Frame_Size) = Golden'Length,
         Message   => "exec-request frame length differs");
      Encode_Exec_Request
        (Request      => Expected,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Assert (Condition => Data = Golden,
              Message   => "exec-request golden bytes differ");

      Decode_Exec_Request
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert (Condition => Decoded = Expected,
              Message   => "decoded exec request differs");
   end Exec_Golden_Data;

   -------------------------------------------------------------------------

   procedure Exec_Merged_Golden_Data
   is
      --  Independent byte oracle: mode 1 carries /o, mode 2 carries no path.
      --  The frame length equals the old split-stream example by coincidence.
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 62) :=
        (16#53#, 16#50#, 16#57#, 16#4e#,
         16#00#, 16#02#, 16#00#, 16#02#,
         16#00#, 16#00#, 16#00#, 16#32#,
         16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
         16#00#, 16#00#, 16#00#, 16#01#,
         16#00#, 16#00#, 16#00#, 16#01#, 16#61#,
         16#00#, 16#00#, 16#00#, 16#01#,
         16#00#, 16#00#, 16#00#, 16#01#, 16#45#,
         16#00#, 16#00#, 16#00#, 16#01#, 16#56#,
         16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#6f#,
         16#02#,
         16#ff#, 16#ff#, 16#ff#, 16#ff#,
         16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Expected : Exec_Request_Type;
      Decoded  : Exec_Request_Type;
      Data     : Ada.Streams.Stream_Element_Array (Golden'Range);
   begin
      Expected.Executable := Ada.Strings.Unbounded.To_Unbounded_String ("/x");
      Expected.Arguments.Append ("a");
      Expected.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String ("V")));
      Expected.Directory := Ada.Strings.Unbounded.To_Unbounded_String ("/");
      Expected.Standard_Output :=
        (Mode => Truncate_File,
         Path => Ada.Strings.Unbounded.To_Unbounded_String ("/o"));
      Expected.Standard_Error := (Mode => Merge_Stdout);
      Expected.Timeout := -1;
      Assert (Exec_Request_Frame_Length (Expected, Maximum_Frame_Size) = 62,
              "shared stream frame length differs");
      Encode_Exec_Request (Expected, Maximum_Frame_Size, Data);
      Assert (Data = Golden, "shared stream encoding differs from oracle");
      Decode_Exec_Request (Golden, Maximum_Frame_Size, Decoded);
      Assert (Decoded = Expected, "shared stream decoding differs");

      Expected.Standard_Output := (Mode => Merge_Stdout);
      begin
         declare
            Length : constant Positive := Exec_Request_Frame_Length
              (Expected, Maximum_Frame_Size);
         begin
            Fail ("stdout self-reference accepted, length" & Length'Image);
         end;
      exception
         when Request_Error => null;
      end;
   end Exec_Merged_Golden_Data;

   -------------------------------------------------------------------------

   procedure Exec_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 62)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#32#,
            16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#61#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#45#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#56#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#00#,
            16#01#, 16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#65#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : Exec_Request_Type;

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as structurally invalid.

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as semantically invalid.

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Exec_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject_Protocol;

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Exec_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Request_Error => null;
         end;
      end Reject_Request;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 1;
         Reject_Protocol (Data => Data, Name => "wrong exec message kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (47) := 3;
         Reject_Protocol (Data => Data, Name => "unknown stream mode");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (47) := 2;
         Reject_Request (Data => Data, Name => "stdout self-reference");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 22)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#02#,
               16#00#, 16#00#, 16#00#, 16#0a#,
               16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
               16#00#, 16#00#, 16#04#, 16#01#);
      begin
         Reject_Request (Data => Data, Name => "oversized argument count");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (17) := Character'Pos ('x');
         Reject_Request (Data => Data, Name => "relative executable");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (36) := Character'Pos ('=');
         Reject_Request (Data => Data, Name => "invalid environment name");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (46) := Character'Pos ('w');
         Reject_Request (Data => Data, Name => "relative directory");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (53) := Character'Pos ('e');
         Reject_Request (Data => Data, Name => "relative stream path");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 61);
      begin
         Data (12) := 16#31#;
         Reject_Protocol (Data => Data, Name => "truncated exec timeout");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array (1 .. 63) := (others => 0);
      begin
         Data (1 .. 62) := Golden;
         Data (12) := 16#33#;
         Reject_Protocol (Data => Data, Name => "trailing exec data");
      end;
   end Exec_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Exec_Roundtrip_And_Bounds
   is
      Request : Exec_Request_Type;
      Decoded : Exec_Request_Type;
   begin
      Request.Executable := Ada.Strings.Unbounded.To_Unbounded_String
        ("/usr/bin/printf");
      Request.Arguments.Append ("");
      Request.Arguments.Append
        ("spaces" & ASCII.HT & "quotes '"" glob *" & ASCII.LF);
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("A"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String
            ("one" & ASCII.LF & "two")));
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("A"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String ("replacement")));
      Request.Directory := Ada.Strings.Unbounded.To_Unbounded_String
        ("/tmp/work area");
      Request.Standard_Output :=
        (Mode => Truncate_File,
         Path => Ada.Strings.Unbounded.To_Unbounded_String ("/tmp/out file"));
      Request.Standard_Error := (Mode => Null_Stream);
      Request.Timeout := Timeout_Milliseconds'Last;
      declare
         Length : constant Positive := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Exec_Request
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert (Condition => Decoded = Request,
                 Message   => "exec request did not round trip");
      end;

      Request.Arguments.Clear;
      Request.Environment.Clear;
      Request.Executable := Ada.Strings.Unbounded.To_Unbounded_String ("/x");
      Request.Directory := Ada.Strings.Unbounded.To_Unbounded_String ("/");
      Request.Standard_Output := (Mode => Null_Stream);
      Request.Standard_Error := (Mode => Null_Stream);
      Request.Timeout := 0;
      for Index in 1 .. Maximum_Vector_Length loop
         Request.Arguments.Append ("");
         Request.Environment.Append
           ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
             Value => Ada.Strings.Unbounded.Null_Unbounded_String));
      end loop;
      declare
         Length : constant Positive := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Exec_Request
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert (Condition => Decoded = Request,
                 Message   => "maximum exec vectors did not round trip");
      end;

      Request.Arguments.Append ("");
      declare
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded argument vector accepted");
      exception
         when Request_Error => null;
      end;

      Request.Arguments.Delete_Last;
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
          Value => Ada.Strings.Unbounded.Null_Unbounded_String));
      declare
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded environment accepted");
      exception
         when Request_Error => null;
      end;
   end Exec_Roundtrip_And_Bounds;

   -------------------------------------------------------------------------

   procedure Failure_Stage_Golden_Data
   is
      type Stage_Code_Array is array (Failure_Stage) of Natural;
      Codes : constant Stage_Code_Array
        := (No_Failure          => 0,
            Enable_Subreaper    => 1,
            Create_Error_Pipe   => 2,
            Fork_Child          => 3,
            Process_Group       => 4,
            Parent_Death        => 5,
            Open_Stdin          => 6,
            Open_Stdout         => 7,
            Open_Stderr         => 8,
            Duplicate_Stdin     => 9,
            Duplicate_Stdout    => 10,
            Duplicate_Stderr    => 11,
            Change_Directory    => 12,
            Reset_Signals       => 13,
            Close_Descriptors   => 14,
            Exec_Target         => 15,
            Wait_Child          => 16,
            Terminate_Group     => 17);
      --  Independent one-based locations derived from the documented frame:
      --  twelve header bytes, one result-kind byte, then the stage u16.
      Stage_High : constant Ada.Streams.Stream_Element_Offset := 14;
      Stage_Low  : constant Ada.Streams.Stream_Element_Offset := 15;
   begin
      for Stage in Failure_Stage loop
         declare
            Expected : constant Result_Type
              := (Kind    => Spawn_Failed,
                  Failure =>
                    (Stage        => Stage,
                     Error_Number => 0,
                     Diagnostic   =>
                       Ada.Strings.Unbounded.Null_Unbounded_String));
            Data : Ada.Streams.Stream_Element_Array (1 .. 23);
            Decoded : Result_Type;
         begin
            Encode_Result
              (Result       => Expected,
               Active_Bound => Maximum_Frame_Size,
               Data         => Data);
            Assert
              (Condition => Data (Stage_High) = 0
                 and then Natural (Data (Stage_Low)) = Codes (Stage),
               Message   => "failure stage code differs for "
                 & Stage'Image);

            Data (Stage_High) := 0;
            Data (Stage_Low) := Ada.Streams.Stream_Element (Codes (Stage));
            Decode_Result
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Result       => Decoded);
            Assert (Condition => Decoded = Expected,
                    Message   => "failure stage decode differs for "
                      & Stage'Image);
         end;
      end loop;
   end Failure_Stage_Golden_Data;

   -------------------------------------------------------------------------

   procedure Header_Bounds
   is
      Header : Header_Type;
      Data   : Ada.Streams.Stream_Element_Array (1 .. Header_Size);
   begin
      Encode_Header
        (Header => (Kind           => Shell_Request,
                    Payload_Length => Maximum_Frame_Size - Header_Size),
         Data   => Data);
      Decode_Header
        (Data         => Data,
         Active_Bound => Maximum_Frame_Size,
         Header       => Header);
      Assert
        (Condition => Header.Payload_Length
           = Maximum_Frame_Size - Header_Size,
         Message   => "maximum frame rejected");

      begin
         Decode_Header
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size - 1,
            Header       => Header);
         Fail (Message => "oversized active frame accepted");
      exception
         when Protocol_Error => null;
      end;

      begin
         Validate_Active_Bound (Active_Bound => Maximum_Frame_Size + 1);
         Fail (Message => "oversized active bound accepted");
      exception
         when Protocol_Error => null;
      end;

      begin
         Encode_Header
           (Header =>
              (Kind           => Shell_Request,
               Payload_Length => Maximum_Frame_Size - Header_Size + 1),
            Data   => Data);
         Fail (Message => "oversized encoded frame accepted");
      exception
         when Protocol_Error => null;
      end;
   end Header_Bounds;

   -------------------------------------------------------------------------

   procedure Header_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. Header_Size)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#24#);
      Data   : Ada.Streams.Stream_Element_Array (1 .. Header_Size);
      Header : Header_Type;
   begin
      Encode_Header
        (Header => (Kind => Exec_Request, Payload_Length => 16#24#),
         Data   => Data);
      Assert (Condition => Data = Golden,
              Message   => "header golden bytes differ");
      Decode_Header
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Header       => Header);
      Assert (Condition => Header.Kind = Exec_Request,
              Message   => "decoded message kind differs");
      Assert (Condition => Header.Payload_Length = 16#24#,
              Message   => "decoded payload length differs");
   end Header_Golden_Data;

   -------------------------------------------------------------------------

   procedure Header_Rejects_Invalid_Data
   is
      Valid : constant Ada.Streams.Stream_Element_Array (1 .. Header_Size)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#00#);
      Header : Header_Type;

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as an invalid header identified by Name.

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Header
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Header       => Header);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (1) := 0;
         Reject (Data => Data, Name => "invalid magic");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (6) := 1;
         Reject (Data => Data, Name => "released version 1");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (8) := 4;
         Reject (Data => Data, Name => "invalid kind");
      end;
      Reject (Data => Valid (1 .. Header_Size - 1), Name => "short header");
   end Header_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn protocol tests");
      T.Add_Test_Routine
        (Routine => Exec_Golden_Data'Access,
         Name    => "Encode and decode golden exec request");
      T.Add_Test_Routine
        (Routine => Exec_Merged_Golden_Data'Access,
         Name    => "Encode and decode shared stderr request");
      T.Add_Test_Routine
        (Routine => Exec_Roundtrip_And_Bounds'Access,
         Name    => "Round trip bounded exec request");
      T.Add_Test_Routine
        (Routine => Exec_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid exec requests");
      T.Add_Test_Routine
        (Routine => Header_Golden_Data'Access,
         Name    => "Encode and decode golden header");
      T.Add_Test_Routine
        (Routine => Header_Bounds'Access,
         Name    => "Enforce header frame bounds");
      T.Add_Test_Routine
        (Routine => Header_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid headers");
      T.Add_Test_Routine
        (Routine => Result_Golden_Data'Access,
         Name    => "Encode and decode golden results");
      T.Add_Test_Routine
        (Routine => Failure_Stage_Golden_Data'Access,
         Name    => "Pin spawn-failure stage numbers");
      T.Add_Test_Routine
        (Routine => Result_Roundtrip_Alternatives'Access,
         Name    => "Round trip result alternatives");
      T.Add_Test_Routine
        (Routine => Result_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid results");
      T.Add_Test_Routine
        (Routine => Shell_Golden_Data'Access,
         Name    => "Encode and decode golden shell request");
      T.Add_Test_Routine
        (Routine => Shell_Roundtrip_And_Bounds'Access,
         Name    => "Round trip bounded shell request");
      T.Add_Test_Routine
        (Routine => Shell_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid shell requests");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Result_Golden_Data
   is
      procedure Check
        (Expected : Result_Type;
         Golden   : Ada.Streams.Stream_Element_Array;
         Name     : String);
      --  Compare both encoding directions with one independently written
      --  complete frame from the version 1 field table.

      procedure Check
        (Expected : Result_Type;
         Golden   : Ada.Streams.Stream_Element_Array;
         Name     : String)
      is
         Data    : Ada.Streams.Stream_Element_Array (Golden'Range);
         Decoded : Result_Type;
      begin
         Assert
           (Condition => Result_Frame_Length
              (Result       => Expected,
               Active_Bound => Maximum_Frame_Size) = Golden'Length,
            Message   => Name & " frame length differs");
         Encode_Result
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Assert (Condition => Data = Golden,
                 Message   => Name & " golden bytes differ");

         Decode_Result
           (Data         => Golden,
            Active_Bound => Maximum_Frame_Size,
            Result       => Decoded);
         Assert (Condition => Decoded = Expected,
                 Message   => Name & " decoded result differs");
      end Check;
   begin
      Check
        (Expected => (Kind => Exited, Exit_Status => 16#fedc_ba98#),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#05#,
            16#00#, 16#fe#, 16#dc#, 16#ba#, 16#98#),
         Name     => "exit result");
      Check
        (Expected => (Kind => Signaled, Signal_Number => 15),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#03#,
            16#01#, 16#00#, 16#0f#),
         Name     => "signal result");
      Check
        (Expected => (Kind => Timed_Out),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#02#),
         Name     => "timeout result");
      Check
        (Expected =>
           (Kind    => Spawn_Failed,
            Failure =>
              (Stage        => Exec_Target,
               Error_Number => 2,
               Diagnostic   => Ada.Strings.Unbounded.To_Unbounded_String
                 ("exec"))),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#0f#,
            16#03#, 16#00#, 16#0f#,
            16#00#, 16#00#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#04#,
            16#65#, 16#78#, 16#65#, 16#63#),
         Name     => "spawn-failure result");
      Check
        (Expected =>
           (Kind       => Request_Rejected,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad request")),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#10#,
            16#04#, 16#00#, 16#00#, 16#00#, 16#0b#,
            16#62#, 16#61#, 16#64#, 16#20#, 16#72#, 16#65#,
            16#71#, 16#75#, 16#65#, 16#73#, 16#74#),
         Name     => "request-rejection result");
      Check
        (Expected =>
           (Kind       => Protocol_Failed,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad frame")),
         Golden   =>
           (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#0e#,
            16#05#, 16#00#, 16#00#, 16#00#, 16#09#,
            16#62#, 16#61#, 16#64#, 16#20#, 16#66#,
            16#72#, 16#61#, 16#6d#, 16#65#),
         Name     => "protocol-failure result");
   end Result_Golden_Data;

   procedure Result_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 27)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#0f#,
            16#03#, 16#00#, 16#0f#,
            16#00#, 16#00#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#04#,
            16#65#, 16#78#, 16#65#, 16#63#);
      Result : Result_Type;

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as an invalid result.

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Result
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Result       => Result);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 1;
         Reject (Data => Data, Name => "wrong result message kind");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 13)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#01#,
               16#06#);
      begin
         Reject (Data => Data, Name => "unknown result kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (15) := 16#12#;
         Reject (Data => Data, Name => "unknown failure stage");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 26);
      begin
         Data (12) := 16#0e#;
         Reject (Data => Data, Name => "truncated result diagnostic");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 14)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#02#,
               16#02#, 16#00#);
      begin
         Reject (Data => Data, Name => "trailing result data");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 17)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#05#,
               16#05#, 16#00#, 16#00#, 16#10#, 16#01#);
      begin
         Reject (Data => Data, Name => "oversized result diagnostic");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (24) := 0;
         Reject (Data => Data, Name => "NUL result diagnostic");
      end;
   end Result_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Result_Roundtrip_Alternatives
   is
      procedure Check (Expected : Result_Type; Name : String);
      --  Assert that Expected retains its discriminant and complete payload.

      procedure Check (Expected : Result_Type; Name : String)
      is
         Length : constant Positive := Result_Frame_Length
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Decoded : Result_Type;
      begin
         Encode_Result
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Result
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Result       => Decoded);
         Assert (Condition => Decoded = Expected,
                 Message   => Name & " did not round trip");
      end Check;
   begin
      Check (Expected => (Kind => Exited, Exit_Status => 16#fedc_ba98#),
             Name     => "exit result");
      Check (Expected => (Kind => Signaled, Signal_Number => 15),
             Name     => "signal result");
      Check (Expected => (Kind => Timed_Out),
             Name     => "timeout result");
      Check
        (Expected =>
           (Kind    => Spawn_Failed,
            Failure =>
              (Stage        => Open_Stdout,
               Error_Number => 13,
               Diagnostic   => Ada.Strings.Unbounded.To_Unbounded_String
                 ("permission denied"))),
         Name => "spawn-failure result");
      Check
        (Expected =>
           (Kind       => Request_Rejected,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad request")),
         Name => "request-rejection result");
      Check
        (Expected =>
           (Kind       => Protocol_Failed,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad frame")),
         Name => "protocol-failure result");

      declare
         Maximum : constant String (1 .. Maximum_Diagnostic_Size)
           := (others => 'd');
      begin
         Check
           (Expected =>
              (Kind       => Protocol_Failed,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 (Maximum)),
            Name => "maximum diagnostic");
      end;

      declare
         Too_Long : constant String (1 .. Maximum_Diagnostic_Size + 1)
           := (others => 'd');
         Invalid : constant Result_Type
           := (Kind       => Protocol_Failed,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 (Too_Long));
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Result_Frame_Length
           (Result       => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded result diagnostic accepted");
      exception
         when Protocol_Error => null;
      end;

      declare
         Invalid : constant Result_Type
           := (Kind       => Request_Rejected,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 ("a" & ASCII.NUL & "b"));
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Result_Frame_Length
           (Result       => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "encoded result diagnostic with NUL accepted");
      exception
         when Protocol_Error => null;
      end;
   end Result_Roundtrip_Alternatives;

   -------------------------------------------------------------------------

   procedure Shell_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 38)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#1a#,
            16#00#, 16#00#, 16#00#, 16#09#,
            16#2f#, 16#62#, 16#69#, 16#6e#,
            16#2f#, 16#74#, 16#72#, 16#75#, 16#65#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : constant Shell_Request_Type
        := (Command   => Ada.Strings.Unbounded.To_Unbounded_String
                          ("/bin/true"),
            Directory => Ada.Strings.Unbounded.To_Unbounded_String ("/"),
            Timeout   => -1);
      Data    : Ada.Streams.Stream_Element_Array (Golden'Range);
      Decoded : Shell_Request_Type;
   begin
      Assert
        (Condition => Shell_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size) = Golden'Length,
         Message   => "shell-request frame length differs");
      Encode_Shell_Request
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Assert (Condition => Data = Golden,
              Message   => "shell-request golden bytes differ");

      Decode_Shell_Request
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Command)
           = "/bin/true",
         Message   => "decoded shell command differs");
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Directory)
           = "/",
         Message   => "decoded shell directory differs");
      Assert (Condition => Decoded.Timeout = -1,
              Message   => "decoded shell timeout differs");
   end Shell_Golden_Data;

   -------------------------------------------------------------------------

   procedure Shell_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 38)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#02#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#1a#,
            16#00#, 16#00#, 16#00#, 16#09#,
            16#2f#, 16#62#, 16#69#, 16#6e#,
            16#2f#, 16#74#, 16#72#, 16#75#, 16#65#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : Shell_Request_Type;

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as structurally invalid.

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as semantically invalid.

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Shell_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject_Protocol;

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Shell_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Request_Error => null;
         end;
      end Reject_Request;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 2;
         Reject_Protocol (Data => Data, Name => "wrong shell kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 37);
      begin
         Data (12) := 16#19#;
         Reject_Protocol (Data => Data, Name => "truncated shell timeout");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array (1 .. 39) := (others => 0);
      begin
         Data (1 .. 38) := Golden;
         Data (12) := 16#1b#;
         Reject_Protocol (Data => Data, Name => "trailing shell data");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (17) := 0;
         Reject_Request (Data => Data, Name => "NUL shell command");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (38) := 16#fe#;
         Reject_Request (Data => Data, Name => "negative shell timeout");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 28)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#10#,
               16#00#, 16#00#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#00#, 16#00#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#);
      begin
         Reject_Request (Data => Data, Name => "empty shell command");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 29)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#11#,
               16#00#, 16#00#, 16#00#, 16#01#, 16#78#,
               16#00#, 16#00#, 16#00#, 16#00#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#);
      begin
         Reject_Request (Data => Data, Name => "one-byte shell command");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 16)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#04#,
               16#00#, 16#01#, 16#00#, 16#01#);
      begin
         Reject_Request (Data => Data, Name => "oversized shell string");
      end;
   end Shell_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Shell_Roundtrip_And_Bounds
   is
      Command : constant String := "printf '%s" & ASCII.LF & "' 'a b'";
      Request : constant Shell_Request_Type
        := (Command   => Ada.Strings.Unbounded.To_Unbounded_String (Command),
            Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
            Timeout   => 1_234);
      Length  : constant Positive := Shell_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size);
      Data    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Length));
      Decoded : Shell_Request_Type;
   begin
      Encode_Shell_Request
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Decode_Shell_Request
        (Data         => Data,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Command)
           = Command,
         Message   => "shell command did not round trip");
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Directory)
           = "",
         Message   => "empty shell directory did not round trip");
      Assert (Condition => Decoded.Timeout = 1_234,
              Message   => "shell timeout did not round trip");

      declare
         Maximum : constant String (1 .. Maximum_String_Size)
           := (others => 'x');
         Boundary : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String (Maximum),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Boundary_Length : constant Positive := Shell_Request_Frame_Length
           (Request      => Boundary,
            Active_Bound => Maximum_Frame_Size);
         Boundary_Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Boundary_Length));
      begin
         Encode_Shell_Request
           (Request      => Boundary,
            Active_Bound => Maximum_Frame_Size,
            Data         => Boundary_Data);
         Decode_Shell_Request
           (Data         => Boundary_Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert
           (Condition => Ada.Strings.Unbounded.Length (Decoded.Command)
              = Maximum_String_Size,
            Message   => "maximum shell string did not round trip");
      end;

      declare
         Too_Long : constant String (1 .. Maximum_String_Size + 1)
           := (others => 'x');
         Invalid : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String (Too_Long),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded shell string accepted");
      exception
         when Request_Error => null;
      end;

      declare
         Invalid : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String
                          ("a" & ASCII.NUL & "b"),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "encoded shell string with NUL accepted");
      exception
         when Request_Error => null;
      end;

      declare
         Invalid : constant Shell_Request_Type
           := (Command   => Ada.Strings.Unbounded.Null_Unbounded_String,
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout   => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "empty encoded shell command accepted");
      exception
         when Request_Error => null;
      end;

      declare
         Invalid : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String ("x"),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "one-byte encoded shell command accepted");
      exception
         when Request_Error => null;
      end;
   end Shell_Roundtrip_And_Bounds;

end Spawn.Protocol.Tests;
