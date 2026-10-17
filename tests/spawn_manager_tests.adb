--
--  Process Spawn Manager
--
--  Copyright (C) 2012 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012 secunet Security Networks AG
--
--  This program is free software; you can redistribute it and/or
--  modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation; either version 2
--  of the License, or (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program; if not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
--  USA.
--
--  As a special exception, if other files instantiate generics from this
--  unit,  or  you  link  this  unit  with  other  files  to  produce  an
--  executable   this  unit  does  not  by  itself  cause  the  resulting
--  executable to  be  covered by the  GNU General  Public License.  This
--  exception does  not  however  invalidate  any  other reasons why  the
--  executable file might be covered by the GNU Public License.
--

with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;

with Anet.Sockets;
with Anet.Sockets.Unix;

with Spawn.Protocol;
with Spawn.Transport;

package body Spawn_Manager_Tests is

   use Ada.Strings.Unbounded;
   use Ahven;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type Spawn.Protocol.Failure_Stage;
   use type Spawn.Protocol.Result_Kind;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn manager tests");
      T.Add_Test_Routine
        (Routine => Send_Receive'Access,
         Name    => "Send and receive data");
      T.Add_Test_Routine
        (Routine => Minimum_Bound_Diagnostics'Access,
         Name    => "Bound diagnostics by active frame");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Minimum_Bound_Diagnostics
   is
      Minimum_Shell_Bound : constant := 30;
      Minimum_Exec_Bound  : constant := 47;
      Request_Socket  : Anet.Sockets.Unix.TCP_Socket_Type;
      Protocol_Socket : Anet.Sockets.Unix.TCP_Socket_Type;
      Spawn_Socket    : Anet.Sockets.Unix.TCP_Socket_Type;

      function Receive_Result
        (Socket : Anet.Sockets.Unix.TCP_Socket_Type;
         Bound  : Positive)
         return Spawn.Protocol.Result_Type;
      --  Receive and decode one result under the selected active frame bound.

      function Receive_Result
        (Socket : Anet.Sockets.Unix.TCP_Socket_Type;
         Bound  : Positive)
         return Spawn.Protocol.Result_Type
      is
         Data : constant Ada.Streams.Stream_Element_Array
           := Spawn.Transport.Receive_Frame
             (Descriptor            => Socket.Get_Socket,
              Active_Bound          => Bound,
              First_Byte_Timeout_MS => 1_000);
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Decode_Result
           (Data         => Data,
            Active_Bound => Bound,
            Result       => Result);
         return Result;
      end Receive_Result;
   begin
      Request_Socket.Init;
      Protocol_Socket.Init;
      Spawn_Socket.Init;
      delay 0.3;

      Request_Socket.Connect (Path => "obj/spawn_manager_min_request");
      Request_Socket.Set_Nonblocking_Mode;
      declare
         Empty_Shell : constant Ada.Streams.Stream_Element_Array (1 .. 28)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#10#,
               16#00#, 16#00#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#00#, 16#00#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#,
               16#ff#, 16#ff#, 16#ff#, 16#ff#);
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Transport.Send_Frame
           (Descriptor => Request_Socket.Get_Socket,
            Data       => Empty_Shell);
         Result := Receive_Result
           (Socket => Request_Socket,
            Bound  => Minimum_Shell_Bound);
         Assert (Condition => Result.Kind = Spawn.Protocol.Request_Rejected,
                 Message   => "minimum-bound request rejection missing");
         Assert
           (Condition => Length (Result.Diagnostic) > 0
              and then Length (Result.Diagnostic)
                 <= Minimum_Shell_Bound - 17,
            Message   => "request rejection diagnostic missing or too long");
      end;
      Request_Socket.Close;

      Protocol_Socket.Connect (Path => "obj/spawn_manager_min_protocol");
      Protocol_Socket.Set_Nonblocking_Mode;
      declare
         Invalid : constant Ada.Streams.Stream_Element_Array (1 .. 12)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#00#);
         Result : Spawn.Protocol.Result_Type;
      begin
         Protocol_Socket.Send (Item => Invalid);
         Result := Receive_Result
           (Socket => Protocol_Socket,
            Bound  => Minimum_Shell_Bound);
         Assert (Condition => Result.Kind = Spawn.Protocol.Protocol_Failed,
                 Message   => "minimum-bound protocol failure missing");
         Assert
           (Condition => Length (Result.Diagnostic) > 0
              and then Length (Result.Diagnostic)
                 <= Minimum_Shell_Bound - 17,
            Message   => "protocol failure diagnostic missing or too long");
      end;
      Protocol_Socket.Close;

      Spawn_Socket.Connect (Path => "obj/spawn_manager_min_spawn");
      Spawn_Socket.Set_Nonblocking_Mode;
      declare
         Request : Spawn.Protocol.Exec_Request_Type;
         Result  : Spawn.Protocol.Result_Type;
      begin
         Request.Executable := To_Unbounded_String ("/missing");
         Request.Directory := To_Unbounded_String ("/");
         Request.Timeout := 1_000;
         declare
            Length : constant Positive
              := Spawn.Protocol.Exec_Request_Frame_Length
                (Request      => Request,
                 Active_Bound => Minimum_Exec_Bound);
            Data : Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Length));
         begin
            Assert (Condition => Length = Minimum_Exec_Bound,
                    Message   => "minimum exec frame size changed");
            Spawn.Protocol.Encode_Exec_Request
              (Request      => Request,
               Active_Bound => Minimum_Exec_Bound,
               Data         => Data);
            Spawn.Transport.Send_Frame
              (Descriptor => Spawn_Socket.Get_Socket,
               Data       => Data);
         end;
         Result := Receive_Result
           (Socket => Spawn_Socket,
            Bound  => Minimum_Exec_Bound);
         Assert
           (Condition => Result.Kind = Spawn.Protocol.Spawn_Failed
              and then Result.Failure.Stage = Spawn.Protocol.Exec_Target
              and then Result.Failure.Error_Number = 2,
            Message   => "minimum-bound spawn failure differs");
         Assert
           (Condition => Length (Result.Failure.Diagnostic) > 0
              and then Length (Result.Failure.Diagnostic)
                 <= Minimum_Exec_Bound - 23,
            Message   => "spawn failure diagnostic missing or too long");
      end;
      Spawn_Socket.Close;
   exception
      when others =>
         begin
            Request_Socket.Close;
         exception
            when others => null;
         end;
         begin
            Protocol_Socket.Close;
         exception
            when others => null;
         end;
         begin
            Spawn_Socket.Close;
         exception
            when others => null;
         end;
         raise;
   end Minimum_Bound_Diagnostics;

   -------------------------------------------------------------------------

   procedure Send_Receive
   is
      Socket : Anet.Sockets.Unix.TCP_Socket_Type;

      function Receive_Result return Spawn.Protocol.Result_Type;
      --  Receive and decode one manager result.

      function Receive_Result return Spawn.Protocol.Result_Type
      is
         Data : constant Ada.Streams.Stream_Element_Array
           := Spawn.Transport.Receive_Frame
             (Descriptor            => Socket.Get_Socket,
              Active_Bound          => 8_192,
              First_Byte_Timeout_MS => 1_000);
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Decode_Result
           (Data         => Data,
            Active_Bound => 8_192,
            Result       => Result);
         return Result;
      end Receive_Result;
   begin
      Socket.Init;

      delay 0.3;

      Socket.Connect (Path => "obj/spawn_manager_0");
      Socket.Set_Nonblocking_Mode;

      declare
         Request : constant Spawn.Protocol.Shell_Request_Type
           := (Command   => To_Unbounded_String ("/bin/true"),
               Directory => Null_Unbounded_String,
               Timeout   => -1);
         Length : constant Positive
           := Spawn.Protocol.Shell_Request_Frame_Length
             (Request      => Request,
              Active_Bound => 8_192);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Encode_Shell_Request
           (Request      => Request,
            Active_Bound => 8_192,
            Data         => Data);
         Data (Data'Last) := 16#fe#;
         Spawn.Transport.Send_Frame
           (Descriptor => Socket.Get_Socket,
            Data       => Data);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Request_Rejected,
                 Message   => "request rejection expected");
      end;

      declare
         Request : constant Spawn.Protocol.Shell_Request_Type
           := (Command   => To_Unbounded_String ("/bin/true"),
               Directory => Null_Unbounded_String,
               Timeout   => -1);
         Length : constant Positive
           := Spawn.Protocol.Shell_Request_Frame_Length
             (Request      => Request,
              Active_Bound => 8_192);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Encode_Shell_Request
           (Request      => Request,
            Active_Bound => 8_192,
            Data         => Data);
         Spawn.Transport.Send_Frame
           (Descriptor => Socket.Get_Socket,
            Data       => Data);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Exited,
                 Message   => "exit result expected");
         Assert (Condition => Result.Exit_Status = 0,
                 Message   => "zero exit status expected");
      end;

      declare
         Current_Directory : constant String
           := Ada.Directories.Current_Directory;
         Stdout_Path : constant String
           := Current_Directory & "/obj/manager-structured.stdout";
         Stderr_Path : constant String
           := Current_Directory & "/obj/manager-structured.stderr";
         Request : Spawn.Protocol.Exec_Request_Type;
         Result  : Spawn.Protocol.Result_Type;
      begin
         if Ada.Directories.Exists (Name => Stdout_Path) then
            Ada.Directories.Delete_File (Name => Stdout_Path);
         end if;
         if Ada.Directories.Exists (Name => Stderr_Path) then
            Ada.Directories.Delete_File (Name => Stderr_Path);
         end if;
         Request.Executable := To_Unbounded_String
           (Current_Directory & "/obj/spawn_posix_tests");
         Request.Arguments.Append ("fixture");
         Request.Arguments.Append ("verify");
         Request.Arguments.Append ("");
         Request.Arguments.Append
           ("space" & ASCII.HT & "quote'""\glob*?[$(not-shell)]");
         Request.Environment.Append
           ((Name  => To_Unbounded_String ("ONLY"),
             Value => To_Unbounded_String ("visible value")));
         Request.Environment.Append
           ((Name  => To_Unbounded_String ("EXPECTED_CWD"),
             Value => To_Unbounded_String (Current_Directory)));
         Request.Directory := To_Unbounded_String (Current_Directory);
         Request.Standard_Output :=
           (Mode => Spawn.Protocol.Truncate_File,
            Path => To_Unbounded_String (Stdout_Path));
         Request.Standard_Error :=
           (Mode => Spawn.Protocol.Truncate_File,
            Path => To_Unbounded_String (Stderr_Path));
         Request.Timeout := 1_000;
         declare
            Length : constant Positive
              := Spawn.Protocol.Exec_Request_Frame_Length
                (Request      => Request,
                 Active_Bound => 8_192);
            Data : Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Length));
         begin
            Spawn.Protocol.Encode_Exec_Request
              (Request      => Request,
               Active_Bound => 8_192,
               Data         => Data);
            Spawn.Transport.Send_Frame
              (Descriptor => Socket.Get_Socket,
               Data       => Data);
         end;
         Result := Receive_Result;
         Assert
           (Condition => Result.Kind = Spawn.Protocol.Exited
              and then Result.Exit_Status = 0,
            Message   => "structured manager request failed");
         declare
            Output : Ada.Text_IO.File_Type;
         begin
            Ada.Text_IO.Open
              (File => Output,
               Mode => Ada.Text_IO.In_File,
               Name => Stdout_Path,
               Form => "shared=no");
            Assert
              (Condition => Ada.Text_IO.Get_Line (File => Output)
                 = "verified stdout",
               Message   => "structured stdout differs");
            Ada.Text_IO.Close (File => Output);
            Ada.Text_IO.Open
              (File => Output,
               Mode => Ada.Text_IO.In_File,
               Name => Stderr_Path,
               Form => "shared=no");
            Assert
              (Condition => Ada.Text_IO.Get_Line (File => Output)
                 = "verified stderr",
               Message   => "structured stderr differs");
            Ada.Text_IO.Close (File => Output);
         end;
         Ada.Directories.Delete_File (Name => Stdout_Path);
         Ada.Directories.Delete_File (Name => Stderr_Path);
      end;

      declare
         Invalid : constant Ada.Streams.Stream_Element_Array (1 .. 12)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#00#);
         Result : Spawn.Protocol.Result_Type;
      begin
         Socket.Send (Item => Invalid);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Protocol_Failed,
                 Message   => "protocol failure expected");
      end;

      Socket.Close;
   end Send_Receive;

end Spawn_Manager_Tests;
