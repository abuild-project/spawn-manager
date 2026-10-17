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
with Interfaces.C;
with System;

with Anet.Constants;

with Spawn.Protocol;

package body Spawn.Transport.Tests is

   package C renames Interfaces.C;

   use Ahven;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type C.int;
   use type C.long;

   type Descriptor_Array is array (Natural range 0 .. 1) of aliased C.int
     with Convention => C;

   function C_Close (Descriptor : C.int) return C.int
     with Import,
          Convention    => C,
          External_Name => "close";
   --  Close one raw fixture descriptor.

   function C_Fcntl
     (Descriptor : C.int;
      Command    : C.int;
      Argument   : C.int)
      return C.int
      with Import,
           Convention    => C,
           External_Name => "fcntl";
   --  Read or update flags on one raw fixture descriptor.

   function C_Send
     (Descriptor : C.int;
      Buffer     : System.Address;
      Length     : C.size_t;
      Flags      : C.int)
      return C.long
      with Import,
           Convention    => C,
           External_Name => "send";
   --  Send fixture bytes without exercising Spawn.Transport.

   function C_Socketpair
     (Domain      : C.int;
      Socket_Type : C.int;
      Protocol    : C.int;
      Descriptors : System.Address)
      return C.int
      with Import,
           Convention    => C,
           External_Name => "socketpair";
   --  Create the local descriptor pair used by transport tests.

   function C_Setsockopt
     (Descriptor : C.int;
      Level      : C.int;
      Option     : C.int;
      Value      : System.Address;
      Length     : C.unsigned)
      return C.int
      with Import,
           Convention    => C,
           External_Name => "setsockopt";
   --  Constrain a fixture socket option through the native interface.

   procedure Set_Receive_Chunk_Limit (Descriptor : C.int)
     with Import,
          Convention    => C,
          External_Name => "spawn_test_limit_receive_chunks";
   --  Limit one fixture socket's recv calls to one byte, or disable with -1.

   Test_Frame : constant Ada.Streams.Stream_Element_Array (1 .. 13)
     := (16#53#, 16#50#, 16#57#, 16#4e#,
         16#00#, 16#02#, 16#00#, 16#03#,
         16#00#, 16#00#, 16#00#, 16#01#,
         16#02#);

   procedure Close_Pair (Descriptors : in out Descriptor_Array);
   --  Close both fixture descriptors, including partially opened pairs.

   procedure Open_Pair (Descriptors : out Descriptor_Array);
   --  Create one nonblocking local stream-socket pair.

   procedure Raw_Send
     (Descriptor : C.int;
      Data       : Ada.Streams.Stream_Element_Array);
   --  Send all fixture bytes without using the transport under test.

   procedure Set_Nonblocking (Descriptor : C.int);
   --  Enable nonblocking mode on one fixture descriptor.

   procedure Set_Send_Buffer (Descriptor : C.int; Size : Positive);
   --  Constrain one fixture send buffer to force partial writes.

   procedure Close_On_Exec_Flag
   is
      F_Getfd     : constant := 1;
      Descriptors : Descriptor_Array;
      Flags       : C.int;
   begin
      Open_Pair (Descriptors => Descriptors);
      Set_Close_On_Exec (Descriptor => Descriptors (0));
      Flags := C_Fcntl
        (Descriptor => Descriptors (0),
         Command    => F_Getfd,
         Argument   => 0);
      Assert (Condition => Flags >= 0 and then Flags mod 2 = 1,
              Message   => "close-on-exec flag not set");
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Close_On_Exec_Flag;

   -------------------------------------------------------------------------

   procedure Close_Pair (Descriptors : in out Descriptor_Array)
   is
      Ignored : C.int;
      pragma Unreferenced (Ignored);
   begin
      for Descriptor of Descriptors loop
         if Descriptor >= 0 then
            Ignored := C_Close (Descriptor => Descriptor);
            Descriptor := -1;
         end if;
      end loop;
   end Close_Pair;

   -------------------------------------------------------------------------

   procedure Completion_Timeout
   is
      Descriptors : Descriptor_Array;
      Writer_Failed : Boolean := False;

      task Writer is
         entry Start;
      end Writer;

      task body Writer
      is
      begin
         accept Start;
         Raw_Send
           (Descriptor => Descriptors (0),
            Data       => Test_Frame (1 .. 1));
         delay 0.100;
         Raw_Send
           (Descriptor => Descriptors (0),
            Data       => Test_Frame (2 .. Test_Frame'Last));
      exception
         when others => Writer_Failed := True;
      end Writer;
   begin
      Open_Pair (Descriptors => Descriptors);
      Writer.Start;
      begin
         declare
            Ignored : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor            => Descriptors (1),
                 Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
                 First_Byte_Timeout_MS => 100,
                 Completion_Timeout_MS => 20);
            pragma Unreferenced (Ignored);
         begin
            Fail (Message => "incomplete frame did not time out");
         end;
      exception
         when Transport_Timeout => null;
      end;
      if not Writer'Terminated then
         abort Writer;
      end if;
      Assert (Condition => not Writer_Failed,
              Message   => "fragment writer failed");
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         if not Writer'Terminated then
            abort Writer;
         end if;
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Completion_Timeout;

   -------------------------------------------------------------------------

   procedure Extra_Data_Is_Rejected
   is
      Descriptors : Descriptor_Array;
      Extra       : constant Ada.Streams.Stream_Element_Array (1 .. 1)
        := (1 => 0);
   begin
      Open_Pair (Descriptors => Descriptors);
      Raw_Send (Descriptor => Descriptors (0), Data => Test_Frame);
      Raw_Send (Descriptor => Descriptors (0), Data => Extra);
      begin
         declare
            Ignored : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor   => Descriptors (1),
                 Active_Bound => Spawn.Protocol.Maximum_Frame_Size);
            pragma Unreferenced (Ignored);
         begin
            Fail (Message => "queued data beyond frame was accepted");
         end;
      exception
         when Extra_Data => null;
      end;
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Extra_Data_Is_Rejected;

   -------------------------------------------------------------------------

   procedure First_Byte_Timeout
   is
      Descriptors : Descriptor_Array;
   begin
      Open_Pair (Descriptors => Descriptors);
      begin
         declare
            Ignored : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor            => Descriptors (1),
                 Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
                 First_Byte_Timeout_MS => 20);
            pragma Unreferenced (Ignored);
         begin
            Fail (Message => "silent peer did not time out");
         end;
      exception
         when Transport_Timeout => null;
      end;
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Close_Pair (Descriptors => Descriptors);
         raise;
   end First_Byte_Timeout;

   -------------------------------------------------------------------------

   procedure Fragmented_Frame
   is
      Descriptors  : Descriptor_Array;
      Writer_Failed : Boolean := False;

      task Writer is
         entry Start;
      end Writer;

      task body Writer
      is
      begin
         accept Start;
         Raw_Send
           (Descriptor => Descriptors (0), Data => Test_Frame (1 .. 1));
         delay 0.010;
         Raw_Send
           (Descriptor => Descriptors (0), Data => Test_Frame (2 .. 5));
         delay 0.010;
         Raw_Send
           (Descriptor => Descriptors (0), Data => Test_Frame (6 .. 12));
         delay 0.010;
         Raw_Send
           (Descriptor => Descriptors (0), Data => Test_Frame (13 .. 13));
      exception
         when others => Writer_Failed := True;
      end Writer;
   begin
      Open_Pair (Descriptors => Descriptors);
      Writer.Start;
      declare
         Frame : constant Ada.Streams.Stream_Element_Array
           := Receive_Frame
             (Descriptor            => Descriptors (1),
              Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
              First_Byte_Timeout_MS => 100,
              Completion_Timeout_MS => 100);
      begin
         Assert (Condition => Frame = Test_Frame,
                 Message   => "fragmented frame differs");
      end;
      Assert (Condition => not Writer_Failed,
              Message   => "fragment writer failed");
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         if not Writer'Terminated then
            abort Writer;
         end if;
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Fragmented_Frame;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn transport tests");
      T.Add_Test_Routine
        (Routine => Close_On_Exec_Flag'Access,
         Name    => "Set close-on-exec flag");
      T.Add_Test_Routine
        (Routine => Send_And_Receive'Access,
         Name    => "Send and receive exact frame");
      T.Add_Test_Routine
        (Routine => Send_Large_Frame'Access,
         Name    => "Send frame larger than socket buffer");
      T.Add_Test_Routine
        (Routine => Fragmented_Frame'Access,
         Name    => "Reassemble fragmented frame");
      T.Add_Test_Routine
        (Routine => First_Byte_Timeout'Access,
         Name    => "Bound first frame byte");
      T.Add_Test_Routine
        (Routine => Completion_Timeout'Access,
         Name    => "Bound incomplete frame");
      T.Add_Test_Routine
        (Routine => Ready_Data_Deadline'Access,
         Name    => "Bound ready frame data");
      T.Add_Test_Routine
        (Routine => Extra_Data_Is_Rejected'Access,
         Name    => "Reject queued bytes after frame");
      T.Add_Test_Routine
        (Routine => Peer_Closure'Access,
         Name    => "Report peer closure");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Open_Pair (Descriptors : out Descriptor_Array)
   is
   begin
      Descriptors := (others => -1);
      if C_Socketpair
        (Domain      => Anet.Constants.Sys.AF_UNIX,
         Socket_Type => Anet.Constants.Sys.SOCK_STREAM,
         Protocol    => 0,
         Descriptors => Descriptors'Address) /= 0
      then
         raise Program_Error with "socketpair failed";
      end if;
      Set_Nonblocking (Descriptor => Descriptors (0));
      Set_Nonblocking (Descriptor => Descriptors (1));
   end Open_Pair;

   -------------------------------------------------------------------------

   procedure Peer_Closure
   is
      Descriptors : Descriptor_Array;
      Ignored     : C.int;
      pragma Unreferenced (Ignored);
   begin
      Open_Pair (Descriptors => Descriptors);
      Ignored := C_Close (Descriptor => Descriptors (0));
      Descriptors (0) := -1;
      begin
         declare
            Data : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor            => Descriptors (1),
                 Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
                 First_Byte_Timeout_MS => 100);
            pragma Unreferenced (Data);
         begin
            Fail (Message => "closed peer was accepted");
         end;
      exception
         when Peer_Closed => null;
      end;
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Peer_Closure;

   -------------------------------------------------------------------------

   procedure Raw_Send
     (Descriptor : C.int;
      Data       : Ada.Streams.Stream_Element_Array)
   is
      Sent : constant C.long := C_Send
        (Descriptor => Descriptor,
         Buffer     => Data'Address,
         Length     => Data'Length,
         Flags      => Anet.Constants.Sys.MSG_NOSIGNAL);
   begin
      if Sent /= Data'Length then
         raise Program_Error with "test fragment send was incomplete";
      end if;
   end Raw_Send;

   -------------------------------------------------------------------------

   procedure Ready_Data_Deadline
   is
      Payload_Length : constant := 20_000;
      Frame : Ada.Streams.Stream_Element_Array
        (1 .. Spawn.Protocol.Header_Size + Payload_Length)
        := (others => 16#a5#);
      Descriptors : Descriptor_Array;
   begin
      Spawn.Protocol.Encode_Header
        (Header =>
           (Kind           => Spawn.Protocol.Result_Message,
            Payload_Length => Payload_Length),
         Data   => Frame);
      Open_Pair (Descriptors => Descriptors);
      Raw_Send (Descriptor => Descriptors (0), Data => Frame);
      Set_Receive_Chunk_Limit (Descriptor => Descriptors (1));
      begin
         declare
            Ignored : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor            => Descriptors (1),
                 Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
                 First_Byte_Timeout_MS => 100,
                 Completion_Timeout_MS => 1);
            pragma Unreferenced (Ignored);
         begin
            Fail (Message => "ready frame data bypassed expired deadline");
         end;
      exception
         when Transport_Timeout => null;
      end;
      Set_Receive_Chunk_Limit (Descriptor => -1);
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Set_Receive_Chunk_Limit (Descriptor => -1);
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Ready_Data_Deadline;

   -------------------------------------------------------------------------

   procedure Send_And_Receive
   is
      Descriptors : Descriptor_Array;
   begin
      Open_Pair (Descriptors => Descriptors);
      Send_Frame (Descriptor => Descriptors (0), Data => Test_Frame);
      declare
         Frame : constant Ada.Streams.Stream_Element_Array
           := Receive_Frame
             (Descriptor   => Descriptors (1),
              Active_Bound => Spawn.Protocol.Maximum_Frame_Size);
      begin
         Assert (Condition => Frame = Test_Frame,
                 Message   => "transported frame differs");
      end;
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Send_And_Receive;

   -------------------------------------------------------------------------

   procedure Send_Large_Frame
   is
      Payload_Length : constant := 120_000;
      Frame : Ada.Streams.Stream_Element_Array
        (1 .. Spawn.Protocol.Header_Size + Payload_Length)
        := (others => 16#a5#);
      Descriptors : Descriptor_Array;
      Reader_Failed  : Boolean := False;
      Reader_Matches : Boolean := False;

      task Reader is
         entry Start;
         entry Done;
      end Reader;

      task body Reader
      is
      begin
         accept Start;
         declare
            Received : constant Ada.Streams.Stream_Element_Array
              := Receive_Frame
                (Descriptor            => Descriptors (1),
                 Active_Bound          => Spawn.Protocol.Maximum_Frame_Size,
                 First_Byte_Timeout_MS => 1_000,
                 Completion_Timeout_MS => 1_000);
         begin
            Reader_Matches := Received = Frame;
         end;
         accept Done;
      exception
         when others =>
            Reader_Failed := True;
            accept Done;
      end Reader;
   begin
      Spawn.Protocol.Encode_Header
        (Header =>
           (Kind           => Spawn.Protocol.Result_Message,
            Payload_Length => Payload_Length),
         Data   => Frame);
      Open_Pair (Descriptors => Descriptors);
      Set_Send_Buffer (Descriptor => Descriptors (0), Size => 1_024);
      Reader.Start;
      Send_Frame
        (Descriptor => Descriptors (0),
         Data       => Frame,
         Timeout_MS => 1_000);
      Reader.Done;
      Assert (Condition => not Reader_Failed,
              Message   => "large-frame reader failed");
      Assert (Condition => Reader_Matches,
              Message   => "large transported frame differs");
      Close_Pair (Descriptors => Descriptors);
   exception
      when others =>
         if not Reader'Terminated then
            abort Reader;
         end if;
         Close_Pair (Descriptors => Descriptors);
         raise;
   end Send_Large_Frame;

   -------------------------------------------------------------------------

   procedure Set_Nonblocking (Descriptor : C.int)
   is
      Flags : C.int;
   begin
      Flags := C_Fcntl
        (Descriptor => Descriptor,
         Command    => Anet.Constants.Sys.F_GETFL,
         Argument   => 0);
      if Flags < 0
        or else C_Fcntl
          (Descriptor => Descriptor,
           Command    => Anet.Constants.Sys.F_SETFL,
           Argument   => Flags + Anet.Constants.Sys.FNDELAY) < 0
      then
         raise Program_Error with "fcntl nonblocking failed";
      end if;
   end Set_Nonblocking;

   -------------------------------------------------------------------------

   procedure Set_Send_Buffer (Descriptor : C.int; Size : Positive)
   is
      Value : aliased C.int := C.int (Size);
   begin
      if C_Setsockopt
        (Descriptor => Descriptor,
         Level      => Anet.Constants.Sys.SOL_SOCKET,
         Option     => Anet.Constants.Sys.SO_SNDBUF,
         Value      => Value'Address,
         Length     => C.unsigned (C.int'Size / System.Storage_Unit)) /= 0
      then
         raise Program_Error with "setsockopt send buffer failed";
      end if;
   end Set_Send_Buffer;

end Spawn.Transport.Tests;
