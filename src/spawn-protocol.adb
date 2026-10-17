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

with Ada.Unchecked_Conversion;

package body Spawn.Protocol is

   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Containers.Count_Type;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   function To_Integer_64 is new Ada.Unchecked_Conversion
     (Source => Interfaces.Unsigned_64,
      Target => Interfaces.Integer_64);
   --  Interpret the fixed i64 wire bits as two's-complement signed data.

   function To_Unsigned_64 is new Ada.Unchecked_Conversion
     (Source => Interfaces.Integer_64,
      Target => Interfaces.Unsigned_64);
   --  Preserve an i64 value's two's-complement bits for wire encoding.

   procedure Decode_Diagnostic
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String);
   --  Decode one protocol-valid bounded diagnostic and advance Cursor.

   procedure Decode_Stream
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Stream : out Stream_Specification_Type);
   --  Decode one stream specification and advance Cursor.

   function Decode_I64
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Integer_64;
   --  Decode one two's-complement big-endian signed 64-bit field at First.

   procedure Decode_String
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String);
   --  Decode one bounded non-NUL string and advance Cursor.

   function Decode_U16
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_16;
   --  Decode one big-endian unsigned 16-bit field at First.

   function Decode_U32
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_32;
   --  Decode one big-endian unsigned 32-bit field at First.

   procedure Encode_U16
     (Value :     Interfaces.Unsigned_16;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one big-endian unsigned 16-bit field at First.

   procedure Encode_Diagnostic
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset);
   --  Encode one validated result diagnostic and advance Cursor.

   procedure Encode_Stream
     (Stream :     Stream_Specification_Type;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset);
   --  Encode one validated stream specification and advance Cursor.

   procedure Encode_I64
     (Value :     Interfaces.Integer_64;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one two's-complement big-endian signed 64-bit field at First.

   procedure Encode_String
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset);
   --  Encode one validated string and advance Cursor.

   procedure Encode_U32
     (Value :     Interfaces.Unsigned_32;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one big-endian unsigned 32-bit field at First.

   function Kind_From_Wire
     (Value : Interfaces.Unsigned_16)
      return Message_Kind;
   --  Decode one assigned message-kind value.

   function Kind_To_Wire
     (Kind : Message_Kind)
      return Interfaces.Unsigned_16;
   --  Return the fixed wire value for Kind.

   function Diagnostic_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive;
   --  Return the encoded diagnostic length after validating its bound.

   function String_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive;
   --  Return the encoded string length after validating its semantic bound.

   function Stream_Field_Length (Stream : Stream_Specification_Type)
      return Positive;
   --  Return the encoded stream-specification length.

   procedure Require_Remaining
     (Data    : Ada.Streams.Stream_Element_Array;
      Cursor  : Ada.Streams.Stream_Element_Offset;
      Count   : Ada.Streams.Stream_Element_Offset;
      Message : String);
   --  Require Count readable bytes at Cursor or raise Protocol_Error.

   procedure Validate_Absolute_Path (Value : String; Name : String);
   --  Reject an empty or non-absolute protocol path.

   procedure Validate_Diagnostic
     (Value : Ada.Strings.Unbounded.Unbounded_String);
   --  Reject a diagnostic which exceeds the unchanged protocol bounds.

   procedure Validate_Environment_Name
     (Value : Ada.Strings.Unbounded.Unbounded_String);
   --  Reject an empty environment name or one containing equals.

   procedure Validate_Frame_Payload
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive);
   --  Reject a payload whose complete frame exceeds the active bound.

   procedure Validate_Shell_Command
     (Value : Ada.Strings.Unbounded.Unbounded_String);
   --  Preserve the compatible shell path's two-byte command minimum.

   procedure Validate_Stream (Stream : Stream_Specification_Type);
   --  Reject a stream specification which cannot be encoded.

   procedure Validate_String
     (Value : Ada.Strings.Unbounded.Unbounded_String);
   --  Reject a string which exceeds the unchanged protocol bounds.

   procedure Validate_Vector_Length
     (Length : Ada.Containers.Count_Type;
      Name   : String);
   --  Reject a vector count beyond the unchanged protocol bound.

   procedure Decode_Diagnostic
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String)
   is
      Length : Natural;
   begin
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => U32_Size,
         Message => "truncated diagnostic length");
      declare
         Raw_Length : constant Interfaces.Unsigned_32
           := Decode_U32 (Data => Data, First => Cursor);
      begin
         if Raw_Length > Maximum_Diagnostic_Size then
            raise Protocol_Error with "diagnostic exceeds protocol bound";
         end if;
         Length := Natural (Raw_Length);
      end;
      Cursor := Cursor + U32_Size;
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => Ada.Streams.Stream_Element_Offset (Length),
         Message => "truncated diagnostic data");
      declare
         Decoded : String (1 .. Length);
      begin
         for Index in Decoded'Range loop
            Decoded (Index) := Character'Val (Data (Cursor));
            if Decoded (Index) = ASCII.NUL then
               raise Protocol_Error with "diagnostic contains NUL";
            end if;
            Cursor := Cursor + 1;
         end loop;
         Value := Ada.Strings.Unbounded.To_Unbounded_String (Decoded);
      end;
   end Decode_Diagnostic;

   -------------------------------------------------------------------------

   procedure Decode_Exec_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Exec_Request_Type)
   is
      Header  : Header_Type;
      Cursor  : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
      Decoded : Exec_Request_Type;
   begin
      if Data'Length < Header_Size then
         raise Protocol_Error with "exec frame shorter than header";
      end if;
      Decode_Header
        (Data         => Data (Data'First .. Data'First + Header_Size - 1),
         Active_Bound => Active_Bound,
         Header       => Header);
      if Header.Kind /= Exec_Request then
         raise Protocol_Error with "exec request has wrong message kind";
      end if;
      if Frame_Length
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Active_Bound) /= Data'Length
      then
         raise Protocol_Error with "exec frame length mismatch";
      end if;

      Decode_String
        (Data   => Data,
         Cursor => Cursor,
         Value  => Decoded.Executable);
      Validate_Absolute_Path
        (Value => Ada.Strings.Unbounded.To_String (Decoded.Executable),
         Name  => "executable");

      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => U32_Size,
         Message => "truncated argument count");
      declare
         Count : constant Interfaces.Unsigned_32
           := Decode_U32 (Data => Data, First => Cursor);
      begin
         if Count > Maximum_Vector_Length then
            raise Request_Error with "argument vector exceeds protocol bound";
         end if;
         Validate_Vector_Length
           (Length => Ada.Containers.Count_Type (Count),
            Name   => "argument");
         Cursor := Cursor + U32_Size;
         for Index in 1 .. Natural (Count) loop
            declare
               Value : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Decode_String
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Value);
               Decoded.Arguments.Append
                 (Ada.Strings.Unbounded.To_String (Value));
            end;
         end loop;
      end;

      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => U32_Size,
         Message => "truncated environment count");
      declare
         Count : constant Interfaces.Unsigned_32
           := Decode_U32 (Data => Data, First => Cursor);
      begin
         if Count > Maximum_Vector_Length then
            raise Request_Error with
              "environment vector exceeds protocol bound";
         end if;
         Validate_Vector_Length
           (Length => Ada.Containers.Count_Type (Count),
            Name   => "environment");
         Cursor := Cursor + U32_Size;
         for Index in 1 .. Natural (Count) loop
            declare
               Environment_Item : Environment_Entry_Type;
            begin
               Decode_String
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Environment_Item.Name);
               Validate_Environment_Name (Value => Environment_Item.Name);
               Decode_String
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Environment_Item.Value);
               Decoded.Environment.Append (Environment_Item);
            end;
         end loop;
      end;

      Decode_String
        (Data   => Data,
         Cursor => Cursor,
         Value  => Decoded.Directory);
      Validate_Absolute_Path
        (Value => Ada.Strings.Unbounded.To_String (Decoded.Directory),
         Name  => "directory");
      Decode_Stream
        (Data   => Data,
         Cursor => Cursor,
         Stream => Decoded.Standard_Output);
      Decode_Stream
        (Data   => Data,
         Cursor => Cursor,
         Stream => Decoded.Standard_Error);
      if Decoded.Standard_Output.Mode = Merge_Stdout then
         raise Request_Error with "stdout cannot refer to itself";
      end if;
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => I64_Size,
         Message => "truncated exec timeout");
      declare
         Raw_Timeout : constant Interfaces.Integer_64
           := Decode_I64 (Data => Data, First => Cursor);
      begin
         if Raw_Timeout < -1 then
            raise Request_Error with "invalid exec timeout";
         end if;
         Decoded.Timeout := Timeout_Milliseconds (Raw_Timeout);
      end;
      Cursor := Cursor + I64_Size;
      if Cursor /= Data'Last + 1 then
         raise Protocol_Error with "trailing exec payload bytes";
      end if;
      Request := Decoded;
   end Decode_Exec_Request;

   -------------------------------------------------------------------------

   procedure Decode_Header
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Header       : out Header_Type)
   is
      First : constant Ada.Streams.Stream_Element_Offset := Data'First;
   begin
      Validate_Active_Bound (Active_Bound => Active_Bound);
      if Data'Length /= Header_Size then
         raise Protocol_Error with "invalid header length";
      end if;
      if Data
        (First + Header_Magic_Offset
         .. First + Header_Magic_Offset + Magic_Size - 1) /= Protocol_Magic
      then
         raise Protocol_Error with "invalid protocol magic";
      end if;
      if Decode_U16
        (Data  => Data,
         First => First + Header_Version_Offset) /= Protocol_Version
      then
         raise Protocol_Error with "unsupported protocol version";
      end if;
      Header.Kind := Kind_From_Wire
        (Value => Decode_U16
           (Data  => Data,
            First => First + Header_Kind_Offset));
      Header.Payload_Length := Decode_U32
        (Data  => Data,
         First => First + Header_Length_Offset);
      Validate_Frame_Payload
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Active_Bound);
   end Decode_Header;

   -------------------------------------------------------------------------

   function Decode_I64
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Integer_64
   is
      Value : Interfaces.Unsigned_64 := 0;
   begin
      for Offset in 0 .. 7 loop
         Value := Interfaces.Shift_Left (Value => Value, Amount => 8)
           or Interfaces.Unsigned_64
             (Data (First + Ada.Streams.Stream_Element_Offset (Offset)));
      end loop;
      return To_Integer_64 (Value);
   end Decode_I64;

   -------------------------------------------------------------------------

   procedure Decode_Result
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Result       : out Result_Type)
   is
      Header : Header_Type;
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
      Decoded_Kind : Result_Kind;
   begin
      if Data'Length < Header_Size then
         raise Protocol_Error with "result frame shorter than header";
      end if;
      Decode_Header
        (Data         => Data (Data'First .. Data'First + Header_Size - 1),
         Active_Bound => Active_Bound,
         Header       => Header);
      if Header.Kind /= Result_Message then
         raise Protocol_Error with "result has wrong message kind";
      end if;
      if Frame_Length
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Active_Bound) /= Data'Length
      then
         raise Protocol_Error with "result frame length mismatch";
      end if;
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => Result_Kind_Size,
         Message => "result kind is missing");
      if Natural (Data (Cursor)) > Result_Kind'Pos (Result_Kind'Last) then
         raise Protocol_Error with "unknown result kind";
      end if;
      Decoded_Kind := Result_Kind'Val (Natural (Data (Cursor)));
      Cursor := Cursor + Result_Kind_Size;

      case Decoded_Kind is
         when Exited =>
            Require_Remaining
              (Data    => Data,
               Cursor  => Cursor,
               Count   => U32_Size,
               Message => "truncated exit status");
            Result :=
              (Kind        => Exited,
               Exit_Status => Decode_U32 (Data => Data, First => Cursor));
            Cursor := Cursor + U32_Size;
         when Signaled =>
            Require_Remaining
              (Data    => Data,
               Cursor  => Cursor,
               Count   => U16_Size,
               Message => "truncated signal number");
            Result :=
              (Kind          => Signaled,
               Signal_Number => Decode_U16 (Data => Data, First => Cursor));
            Cursor := Cursor + U16_Size;
         when Timed_Out =>
            Result := (Kind => Timed_Out);
         when Spawn_Failed =>
            Require_Remaining
              (Data    => Data,
               Cursor  => Cursor,
               Count   => U16_Size + U32_Size,
               Message => "truncated spawn failure");
            declare
               Raw_Stage : constant Interfaces.Unsigned_16
                 := Decode_U16 (Data => Data, First => Cursor);
               Diagnostic : Ada.Strings.Unbounded.Unbounded_String;
            begin
               if Natural (Raw_Stage)
                 > Failure_Stage'Pos (Failure_Stage'Last)
               then
                  raise Protocol_Error with "unknown failure stage";
               end if;
               Cursor := Cursor + U16_Size;
               declare
                  Error_Number : constant Interfaces.Unsigned_32
                    := Decode_U32 (Data => Data, First => Cursor);
               begin
                  Cursor := Cursor + U32_Size;
                  Decode_Diagnostic
                    (Data   => Data,
                     Cursor => Cursor,
                     Value  => Diagnostic);
                  Result :=
                    (Kind    => Spawn_Failed,
                     Failure =>
                       (Stage => Failure_Stage'Val (Natural (Raw_Stage)),
                        Error_Number => Error_Number,
                        Diagnostic => Diagnostic));
               end;
            end;
         when Request_Rejected =>
            declare
               Diagnostic : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Decode_Diagnostic
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Diagnostic);
               Result :=
                 (Kind       => Request_Rejected,
                  Diagnostic => Diagnostic);
            end;
         when Protocol_Failed =>
            declare
               Diagnostic : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Decode_Diagnostic
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Diagnostic);
               Result :=
                 (Kind       => Protocol_Failed,
                  Diagnostic => Diagnostic);
            end;
      end case;

      if Cursor /= Data'Last + 1 then
         raise Protocol_Error with "trailing result payload bytes";
      end if;
   end Decode_Result;

   -------------------------------------------------------------------------

   procedure Decode_Shell_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Shell_Request_Type)
   is
      Header : Header_Type;
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
      Raw_Timeout : Interfaces.Integer_64;
   begin
      if Data'Length < Header_Size then
         raise Protocol_Error with "shell frame shorter than header";
      end if;
      Decode_Header
        (Data         => Data (Data'First .. Data'First + Header_Size - 1),
         Active_Bound => Active_Bound,
         Header       => Header);
      if Header.Kind /= Shell_Request then
         raise Protocol_Error with "shell request has wrong message kind";
      end if;
      if Frame_Length
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Active_Bound) /= Data'Length
      then
         raise Protocol_Error with "shell frame length mismatch";
      end if;

      Decode_String (Data => Data, Cursor => Cursor, Value => Request.Command);
      Validate_Shell_Command (Value => Request.Command);
      Decode_String
        (Data   => Data,
         Cursor => Cursor,
         Value  => Request.Directory);
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => I64_Size,
         Message => "truncated shell timeout");
      Raw_Timeout := Decode_I64 (Data => Data, First => Cursor);
      Cursor := Cursor + I64_Size;
      if Raw_Timeout < -1 then
         raise Request_Error with "invalid shell timeout";
      end if;
      Request.Timeout := Timeout_Milliseconds (Raw_Timeout);
      if Cursor /= Data'Last + 1 then
         raise Protocol_Error with "trailing shell payload bytes";
      end if;
   end Decode_Shell_Request;

   -------------------------------------------------------------------------

   procedure Decode_Stream
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Stream : out Stream_Specification_Type)
   is
   begin
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => Stream_Mode_Size,
         Message => "stream mode is missing");
      case Data (Cursor) is
         when 0 =>
            Stream := (Mode => Null_Stream);
            Cursor := Cursor + Stream_Mode_Size;
         when 1 =>
            Cursor := Cursor + Stream_Mode_Size;
            declare
               Path : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Decode_String
                 (Data   => Data,
                  Cursor => Cursor,
                  Value  => Path);
               Validate_Absolute_Path
                 (Value => Ada.Strings.Unbounded.To_String (Path),
                  Name  => "stream");
               Stream := (Mode => Truncate_File, Path => Path);
            end;
         when 2 =>
            Stream := (Mode => Merge_Stdout);
            Cursor := Cursor + Stream_Mode_Size;
         when others =>
            raise Protocol_Error with "unknown stream mode";
      end case;
   end Decode_Stream;

   -------------------------------------------------------------------------

   procedure Decode_String
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String)
   is
      Length : Natural;
   begin
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => U32_Size,
         Message => "truncated string length");
      declare
         Raw_Length : constant Interfaces.Unsigned_32
           := Decode_U32 (Data => Data, First => Cursor);
      begin
         if Raw_Length > Maximum_String_Size then
            raise Request_Error with "string exceeds protocol bound";
         end if;
         Length := Natural (Raw_Length);
      end;
      Cursor := Cursor + U32_Size;
      Require_Remaining
        (Data    => Data,
         Cursor  => Cursor,
         Count   => Ada.Streams.Stream_Element_Offset (Length),
         Message => "truncated string data");
      declare
         Result : String (1 .. Length);
      begin
         for Index in Result'Range loop
            Result (Index) := Character'Val (Data (Cursor));
            if Result (Index) = ASCII.NUL then
               raise Request_Error with "string contains NUL";
            end if;
            Cursor := Cursor + 1;
         end loop;
         Value := Ada.Strings.Unbounded.To_Unbounded_String (Result);
      end;
   end Decode_String;

   -------------------------------------------------------------------------

   function Decode_U16
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_16
   is
   begin
      return Interfaces.Shift_Left
        (Value  => Interfaces.Unsigned_16 (Data (First)),
         Amount => 8)
        or Interfaces.Unsigned_16 (Data (First + 1));
   end Decode_U16;

   -------------------------------------------------------------------------

   function Decode_U32
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_32
   is
      Result : Interfaces.Unsigned_32 := 0;
   begin
      for Offset in 0 .. 3 loop
         Result := Interfaces.Shift_Left (Value => Result, Amount => 8)
           or Interfaces.Unsigned_32
             (Data (First + Ada.Streams.Stream_Element_Offset (Offset)));
      end loop;
      return Result;
   end Decode_U32;

   -------------------------------------------------------------------------

   function Diagnostic_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      Validate_Diagnostic (Value => Value);
      return U32_Size + Source'Length;
   end Diagnostic_Field_Length;

   -------------------------------------------------------------------------

   procedure Encode_Diagnostic
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset)
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      Validate_Diagnostic (Value => Value);
      Encode_U32
        (Value => Interfaces.Unsigned_32 (Source'Length),
         Data  => Data,
         First => Cursor);
      Cursor := Cursor + U32_Size;
      for Item of Source loop
         Data (Cursor) := Ada.Streams.Stream_Element (Character'Pos (Item));
         Cursor := Cursor + 1;
      end loop;
   end Encode_Diagnostic;

   -------------------------------------------------------------------------

   procedure Encode_Exec_Request
     (Request      :     Exec_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array)
   is
      Length : constant Positive := Exec_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Active_Bound);
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
   begin
      if Data'Length /= Length then
         raise Protocol_Error with "exec frame buffer length mismatch";
      end if;
      Encode_Header
        (Header =>
           (Kind           => Exec_Request,
            Payload_Length => Interfaces.Unsigned_32 (Length - Header_Size)),
         Data   => Data);
      Encode_String
        (Value  => Request.Executable,
         Data   => Data,
         Cursor => Cursor);

      Encode_U32
        (Value => Interfaces.Unsigned_32 (Request.Arguments.Length),
         Data  => Data,
         First => Cursor);
      Cursor := Cursor + U32_Size;
      for Argument of Request.Arguments loop
         Encode_String
           (Value  => Ada.Strings.Unbounded.To_Unbounded_String (Argument),
            Data   => Data,
            Cursor => Cursor);
      end loop;

      Encode_U32
        (Value => Interfaces.Unsigned_32 (Request.Environment.Length),
         Data  => Data,
         First => Cursor);
      Cursor := Cursor + U32_Size;
      for Environment_Item of Request.Environment loop
         Encode_String
           (Value  => Environment_Item.Name,
            Data   => Data,
            Cursor => Cursor);
         Encode_String
           (Value  => Environment_Item.Value,
            Data   => Data,
            Cursor => Cursor);
      end loop;

      Encode_String
        (Value  => Request.Directory,
         Data   => Data,
         Cursor => Cursor);
      Encode_Stream
        (Stream => Request.Standard_Output,
         Data   => Data,
         Cursor => Cursor);
      Encode_Stream
        (Stream => Request.Standard_Error,
         Data   => Data,
         Cursor => Cursor);
      Encode_I64 (Value => Request.Timeout, Data => Data, First => Cursor);
      Cursor := Cursor + I64_Size;
      if Cursor /= Data'Last + 1 then
         raise Program_Error with "exec frame length calculation differs";
      end if;
   end Encode_Exec_Request;

   -------------------------------------------------------------------------

   procedure Encode_Header
     (Header :     Header_Type;
      Data   : in out Ada.Streams.Stream_Element_Array)
   is
      First : constant Ada.Streams.Stream_Element_Offset := Data'First;
   begin
      Validate_Frame_Payload
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Maximum_Frame_Size);
      if Data'Length < Header_Size then
         raise Protocol_Error with "header buffer too small";
      end if;
      Data
        (First + Header_Magic_Offset
         .. First + Header_Magic_Offset + Magic_Size - 1) := Protocol_Magic;
      Encode_U16
        (Value => Protocol_Version,
         Data  => Data,
         First => First + Header_Version_Offset);
      Encode_U16
        (Value => Kind_To_Wire (Kind => Header.Kind),
         Data  => Data,
         First => First + Header_Kind_Offset);
      Encode_U32
        (Value => Header.Payload_Length,
         Data  => Data,
         First => First + Header_Length_Offset);
   end Encode_Header;

   -------------------------------------------------------------------------

   procedure Encode_I64
     (Value :     Interfaces.Integer_64;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
      Raw : constant Interfaces.Unsigned_64 := To_Unsigned_64 (Value);
   begin
      for Offset in 0 .. 7 loop
         Data (First + Ada.Streams.Stream_Element_Offset (Offset))
           := Ada.Streams.Stream_Element
             (Interfaces.Shift_Right
                (Value  => Raw,
                 Amount => (7 - Offset) * 8)
              and 16#ff#);
      end loop;
   end Encode_I64;

   -------------------------------------------------------------------------

   procedure Encode_Result
     (Result       :     Result_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array)
   is
      Length : constant Positive := Result_Frame_Length
        (Result       => Result,
         Active_Bound => Active_Bound);
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
   begin
      if Data'Length /= Length then
         raise Protocol_Error with "result frame buffer length mismatch";
      end if;
      Encode_Header
        (Header =>
           (Kind           => Result_Message,
            Payload_Length => Interfaces.Unsigned_32 (Length - Header_Size)),
         Data   => Data);
      Data (Cursor) := Ada.Streams.Stream_Element
        (Result_Kind'Pos (Result.Kind));
      Cursor := Cursor + Result_Kind_Size;

      case Result.Kind is
         when Exited =>
            Encode_U32
              (Value => Result.Exit_Status,
               Data  => Data,
               First => Cursor);
            Cursor := Cursor + U32_Size;
         when Signaled =>
            Encode_U16
              (Value => Result.Signal_Number,
               Data  => Data,
               First => Cursor);
            Cursor := Cursor + U16_Size;
         when Timed_Out =>
            null;
         when Spawn_Failed =>
            Encode_U16
              (Value => Interfaces.Unsigned_16
                 (Failure_Stage'Pos (Result.Failure.Stage)),
               Data  => Data,
               First => Cursor);
            Cursor := Cursor + U16_Size;
            Encode_U32
              (Value => Result.Failure.Error_Number,
               Data  => Data,
               First => Cursor);
            Cursor := Cursor + U32_Size;
            Encode_Diagnostic
              (Value  => Result.Failure.Diagnostic,
               Data   => Data,
               Cursor => Cursor);
         when Request_Rejected | Protocol_Failed =>
            Encode_Diagnostic
              (Value  => Result.Diagnostic,
               Data   => Data,
               Cursor => Cursor);
      end case;
      if Cursor /= Data'Last + 1 then
         raise Program_Error with "result frame length calculation differs";
      end if;
   end Encode_Result;

   -------------------------------------------------------------------------

   procedure Encode_Shell_Request
     (Request      :     Shell_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array)
   is
      Length : constant Positive := Shell_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Active_Bound);
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
   begin
      if Data'Length /= Length then
         raise Protocol_Error with "shell frame buffer length mismatch";
      end if;
      Encode_Header
        (Header =>
           (Kind           => Shell_Request,
            Payload_Length => Interfaces.Unsigned_32 (Length - Header_Size)),
         Data   => Data);
      Encode_String
        (Value  => Request.Command,
         Data   => Data,
         Cursor => Cursor);
      Encode_String
        (Value  => Request.Directory,
         Data   => Data,
         Cursor => Cursor);
      Encode_I64 (Value => Request.Timeout, Data => Data, First => Cursor);
      Cursor := Cursor + I64_Size;
      if Cursor /= Data'Last + 1 then
         raise Program_Error with "shell frame length calculation differs";
      end if;
   end Encode_Shell_Request;

   -------------------------------------------------------------------------

   procedure Encode_Stream
     (Stream :     Stream_Specification_Type;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset)
   is
   begin
      Validate_Stream (Stream => Stream);
      Data (Cursor) := Ada.Streams.Stream_Element
        (Stream_Mode'Pos (Stream.Mode));
      Cursor := Cursor + Stream_Mode_Size;
      if Stream.Mode = Truncate_File then
         Encode_String
           (Value  => Stream.Path,
            Data   => Data,
            Cursor => Cursor);
      end if;
   end Encode_Stream;

   -------------------------------------------------------------------------

   procedure Encode_String
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset)
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      Validate_String (Value => Value);
      Encode_U32
        (Value => Interfaces.Unsigned_32 (Source'Length),
         Data  => Data,
         First => Cursor);
      Cursor := Cursor + U32_Size;
      for Item of Source loop
         Data (Cursor) := Ada.Streams.Stream_Element
           (Character'Pos (Item));
         Cursor := Cursor + 1;
      end loop;
   end Encode_String;

   -------------------------------------------------------------------------

   procedure Encode_U16
     (Value :     Interfaces.Unsigned_16;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
   begin
      Data (First) := Ada.Streams.Stream_Element
        (Interfaces.Shift_Right (Value => Value, Amount => 8) and 16#ff#);
      Data (First + 1) := Ada.Streams.Stream_Element (Value and 16#ff#);
   end Encode_U16;

   -------------------------------------------------------------------------

   procedure Encode_U32
     (Value :     Interfaces.Unsigned_32;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
   begin
      for Offset in 0 .. 3 loop
         Data (First + Ada.Streams.Stream_Element_Offset (Offset))
           := Ada.Streams.Stream_Element
             (Interfaces.Shift_Right
                (Value  => Value,
                 Amount => (3 - Offset) * 8)
              and 16#ff#);
      end loop;
   end Encode_U32;

   -------------------------------------------------------------------------

   function Exec_Request_Frame_Length
     (Request      : Exec_Request_Type;
      Active_Bound : Positive)
      return Positive
   is
      Payload_Length : Natural := I64_Size;
   begin
      Validate_Vector_Length
        (Length => Request.Arguments.Length,
         Name   => "argument");
      Validate_Vector_Length
        (Length => Request.Environment.Length,
         Name   => "environment");

      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Executable);
      Validate_Absolute_Path
        (Value => Ada.Strings.Unbounded.To_String (Request.Executable),
         Name  => "executable");

      Payload_Length := Payload_Length + U32_Size;
      for Argument of Request.Arguments loop
         Payload_Length := Payload_Length + String_Field_Length
           (Value => Ada.Strings.Unbounded.To_Unbounded_String (Argument));
      end loop;

      Payload_Length := Payload_Length + U32_Size;
      for Environment_Item of Request.Environment loop
         Payload_Length := Payload_Length
           + String_Field_Length (Value => Environment_Item.Name)
           + String_Field_Length (Value => Environment_Item.Value);
         Validate_Environment_Name (Value => Environment_Item.Name);
      end loop;

      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Directory);
      Validate_Absolute_Path
        (Value => Ada.Strings.Unbounded.To_String (Request.Directory),
         Name  => "directory");
      if Request.Standard_Output.Mode = Merge_Stdout then
         raise Request_Error with "stdout cannot refer to itself";
      end if;
      Payload_Length := Payload_Length
        + Stream_Field_Length (Stream => Request.Standard_Output)
        + Stream_Field_Length (Stream => Request.Standard_Error);
      return Frame_Length
        (Payload_Length => Interfaces.Unsigned_32 (Payload_Length),
         Active_Bound   => Active_Bound);
   end Exec_Request_Frame_Length;

   -------------------------------------------------------------------------

   function Frame_Length
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive)
      return Positive
   is
   begin
      Validate_Frame_Payload
        (Payload_Length => Payload_Length,
         Active_Bound   => Active_Bound);
      return Header_Size + Natural (Payload_Length);
   end Frame_Length;

   -------------------------------------------------------------------------

   function Kind_From_Wire
     (Value : Interfaces.Unsigned_16)
      return Message_Kind
   is
   begin
      case Value is
         when 1 => return Shell_Request;
         when 2 => return Exec_Request;
         when 3 => return Result_Message;
         when others =>
            raise Protocol_Error with "unknown message kind";
      end case;
   end Kind_From_Wire;

   -------------------------------------------------------------------------

   function Kind_To_Wire
     (Kind : Message_Kind)
      return Interfaces.Unsigned_16
   is
   begin
      case Kind is
         when Shell_Request  => return 1;
         when Exec_Request   => return 2;
         when Result_Message => return 3;
      end case;
   end Kind_To_Wire;

   -------------------------------------------------------------------------

   procedure Require_Remaining
     (Data    : Ada.Streams.Stream_Element_Array;
      Cursor  : Ada.Streams.Stream_Element_Offset;
      Count   : Ada.Streams.Stream_Element_Offset;
      Message : String)
   is
   begin
      if Count = 0 then
         return;
      elsif Cursor > Data'Last
        or else Data'Last - Cursor + 1 < Count
      then
         raise Protocol_Error with Message;
      end if;
   end Require_Remaining;

   -------------------------------------------------------------------------

   function Result_Frame_Length
     (Result       : Result_Type;
      Active_Bound : Positive)
      return Positive
   is
      Payload_Length : Natural := Result_Kind_Size;
   begin
      case Result.Kind is
         when Exited =>
            Payload_Length := Payload_Length + U32_Size;
         when Signaled =>
            Payload_Length := Payload_Length + U16_Size;
         when Timed_Out =>
            null;
         when Spawn_Failed =>
            Payload_Length := Payload_Length + U16_Size + U32_Size
              + Diagnostic_Field_Length (Result.Failure.Diagnostic);
         when Request_Rejected | Protocol_Failed =>
            Payload_Length := Payload_Length
              + Diagnostic_Field_Length (Result.Diagnostic);
      end case;
      return Frame_Length
        (Payload_Length => Interfaces.Unsigned_32 (Payload_Length),
         Active_Bound   => Active_Bound);
   end Result_Frame_Length;

   -------------------------------------------------------------------------

   function Shell_Request_Frame_Length
     (Request      : Shell_Request_Type;
      Active_Bound : Positive)
      return Positive
   is
      Payload_Length : Natural := I64_Size;
   begin
      Validate_Shell_Command (Value => Request.Command);
      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Command);
      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Directory);
      return Frame_Length
        (Payload_Length => Interfaces.Unsigned_32 (Payload_Length),
         Active_Bound   => Active_Bound);
   end Shell_Request_Frame_Length;

   -------------------------------------------------------------------------

   function Stream_Field_Length (Stream : Stream_Specification_Type)
      return Positive
   is
   begin
      Validate_Stream (Stream => Stream);
      case Stream.Mode is
         when Null_Stream | Merge_Stdout =>
            return Stream_Mode_Size;
         when Truncate_File =>
            declare
               Length : constant Positive := String_Field_Length
                 (Value => Stream.Path);
            begin
               return Stream_Mode_Size + Length;
            end;
      end case;
   end Stream_Field_Length;

   -------------------------------------------------------------------------

   function String_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      Validate_String (Value => Value);
      return U32_Size + Source'Length;
   end String_Field_Length;

   -------------------------------------------------------------------------

   procedure Validate_Absolute_Path (Value : String; Name : String)
   is
   begin
      if Value'Length = 0 or else Value (Value'First) /= '/' then
         raise Request_Error with Name & " path must be absolute";
      end if;
   end Validate_Absolute_Path;

   -------------------------------------------------------------------------

   procedure Validate_Active_Bound (Active_Bound : Positive)
   is
   begin
      if Active_Bound < Header_Size
        or else Active_Bound > Maximum_Frame_Size
      then
         raise Protocol_Error with "invalid active frame bound";
      end if;
   end Validate_Active_Bound;

   -------------------------------------------------------------------------

   procedure Validate_Diagnostic
     (Value : Ada.Strings.Unbounded.Unbounded_String)
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      if Source'Length > Maximum_Diagnostic_Size then
         raise Protocol_Error with "diagnostic exceeds protocol bound";
      end if;
      for Item of Source loop
         if Item = ASCII.NUL then
            raise Protocol_Error with "diagnostic contains NUL";
         end if;
      end loop;
   end Validate_Diagnostic;

   -------------------------------------------------------------------------

   procedure Validate_Environment_Name
     (Value : Ada.Strings.Unbounded.Unbounded_String)
   is
      Name : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      if Name'Length = 0 then
         raise Request_Error with "environment name is empty";
      end if;
      for Item of Name loop
         if Item = '=' then
            raise Request_Error with "environment name contains equals";
         end if;
      end loop;
   end Validate_Environment_Name;

   -------------------------------------------------------------------------

   procedure Validate_Frame_Payload
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive)
   is
      Maximum_Payload : Interfaces.Unsigned_32;
   begin
      Validate_Active_Bound (Active_Bound => Active_Bound);
      Maximum_Payload := Interfaces.Unsigned_32
        (Active_Bound - Header_Size);
      if Payload_Length > Maximum_Payload then
         raise Protocol_Error with "frame exceeds active bound";
      end if;
   end Validate_Frame_Payload;

   -------------------------------------------------------------------------

   procedure Validate_Shell_Command
     (Value : Ada.Strings.Unbounded.Unbounded_String)
   is
   begin
      Validate_String (Value => Value);
      if Ada.Strings.Unbounded.Length (Value)
        < Minimum_Shell_Command_Size
      then
         raise Request_Error with "shell command is shorter than two bytes";
      end if;
   end Validate_Shell_Command;

   -------------------------------------------------------------------------

   procedure Validate_Stream (Stream : Stream_Specification_Type)
   is
   begin
      case Stream.Mode is
         when Null_Stream | Merge_Stdout =>
            null;
         when Truncate_File =>
            Validate_String (Value => Stream.Path);
            Validate_Absolute_Path
              (Value => Ada.Strings.Unbounded.To_String (Stream.Path),
               Name  => "stream");
      end case;
   end Validate_Stream;

   -------------------------------------------------------------------------

   procedure Validate_String
     (Value : Ada.Strings.Unbounded.Unbounded_String)
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      if Source'Length > Maximum_String_Size then
         raise Request_Error with "string exceeds protocol bound";
      end if;
      for Item of Source loop
         if Item = ASCII.NUL then
            raise Request_Error with "string contains NUL";
         end if;
      end loop;
   end Validate_String;

   -------------------------------------------------------------------------

   procedure Validate_Vector_Length
     (Length : Ada.Containers.Count_Type;
      Name   : String)
   is
   begin
      if Length > Maximum_Vector_Length then
         raise Request_Error with Name & " vector exceeds protocol bound";
      end if;
   end Validate_Vector_Length;

end Spawn.Protocol;
