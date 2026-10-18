--
--  Process Spawn Manager
--
--  Copyright (C) 2012, 2015 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012, 2015 secunet Security Networks AG
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

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Streams;
with Ada.Exceptions;
with Interfaces;

with Anet.Sockets;
with Anet.Sockets.Unix;

with Spawn.Logger;
with Spawn.Protocol;
with Spawn.Signals;
with Spawn.Transport;
with Spawn.Version;

with Spawn_Manager_Processes;

procedure Spawn_Manager
is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;

   package Logger renames Spawn.Logger;

   procedure Print_Usage;
   --  Print usage to stdout.

   function To_Protocol_Result
     (Result : Spawn_Manager_Processes.Execution_Result)
      return Spawn.Protocol.Result_Type;
   --  Translate the common execution result without losing termination data.

   function To_Protocol_Stage
     (Stage : Spawn_Manager_Processes.Failure_Stage)
      return Spawn.Protocol.Failure_Stage;
   --  Translate a C-core failure stage without relying on enum positions.

   procedure Run_Server
     (Buffer_Size : Positive;
      Socket_Path : String);
   --  Own the listening socket and serve the manager's single connection.

   -------------------------------------------------------------------------

   procedure Print_Usage
   is
      use Ada.Command_Line;
   begin
      Ada.Text_IO.Put_Line
        (Item => "Spawn Manager, version " & Spawn.Version.Version_String);
      Ada.Text_IO.Put_Line
        (Item => "Usage: " & Command_Name & " <buffer_size> <socket>");
   end Print_Usage;

   -------------------------------------------------------------------------

   procedure Run_Server
     (Buffer_Size : Positive;
      Socket_Path : String)
   is
      Listener   : aliased Anet.Sockets.Unix.TCP_Socket_Type;
      Connection : aliased Anet.Sockets.Unix.TCP_Socket_Type;
   begin
      pragma Debug (Logger.Init_Logfile (Path => Socket_Path & ".log"));
      pragma Debug
        (Logger.Log_File
           (Message => "Starting Spawn Manager (version "
              & Spawn.Version.Version_String & ")"));

      if Buffer_Size < Spawn.Protocol.Minimum_Shell_Request_Frame_Size
        or else Buffer_Size > Spawn.Protocol.Maximum_Frame_Size
      then
         pragma Debug (Logger.Log_File ("Invalid protocol buffer size"));
         Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
         return;
      end if;

      if not Anet.Sockets.Unix.Is_Valid (Path => Socket_Path) then
         pragma Debug
           (Logger.Log_File ("UNIX path too long '" & Socket_Path & "'"));
         Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
         return;
      end if;

      Listener.Init;
      Spawn.Transport.Set_Close_On_Exec
        (Descriptor => Listener.Get_Socket);

      declare
         Signal_Handler : Spawn.Signals.Exit_Handler_Type;
         pragma Unreferenced (Signal_Handler);
         pragma Unreserve_All_Interrupts;

         function Bound_Result_Diagnostic
           (Result : Spawn.Protocol.Result_Type)
            return Spawn.Protocol.Result_Type;
         --  Truncate only diagnostic text so every result fits Buffer_Size.

         procedure Dispatch_Frame
           (Frame : Ada.Streams.Stream_Element_Array);
         --  Decode the common header and dispatch one client request.

         procedure Execute_And_Reply
           (Request : Spawn_Manager_Processes.Execution_Request);
         --  Execute one normalized request, log its result and reply once.

         procedure Handle_Exec_Request
           (Frame : Ada.Streams.Stream_Element_Array);
         --  Decode, report and execute one structured request frame.

         procedure Handle_Shell_Request
           (Frame : Ada.Streams.Stream_Element_Array);
         --  Decode, report and execute one compatible shell request frame.

         procedure Send_Reply (Result : Spawn.Protocol.Result_Type);
         --  Send one exact structured result frame.

         procedure Send_Reply_Protocol_Failure (Diagnostic : String);
         --  Attempt a terminal diagnostic without masking the original error.

         procedure Serve_Connection;
         --  Receive requests until the peer closes or the protocol fails.

         -------------------------------------------------------------------

         function Bound_Result_Diagnostic
           (Result : Spawn.Protocol.Result_Type)
            return Spawn.Protocol.Result_Type
         is
            Basic_Overhead : constant := Spawn.Protocol.Header_Size
              + Spawn.Protocol.Result_Kind_Size + Spawn.Protocol.U32_Size;
            Spawn_Overhead : constant := Basic_Overhead
              + Spawn.Protocol.U16_Size + Spawn.Protocol.U32_Size;

            function Truncate
              (Value  : Unbounded_String;
               Length : Natural)
               return Unbounded_String;
            --  Return at most Length bytes without changing their contents.

            function Truncate
              (Value  : Unbounded_String;
               Length : Natural)
               return Unbounded_String
            is
               Source : constant String := To_String (Value);
               Last   : constant Natural := Natural'Min
                 (Source'Length, Length);
            begin
               if Last = 0 then
                  return Null_Unbounded_String;
               end if;
               return To_Unbounded_String
                 (Source (Source'First .. Source'First + Last - 1));
            end Truncate;
         begin
            case Result.Kind is
               when Spawn.Protocol.Spawn_Failed =>
                  return
                    (Kind    => Spawn.Protocol.Spawn_Failed,
                     Failure =>
                       (Stage        => Result.Failure.Stage,
                        Error_Number => Result.Failure.Error_Number,
                        Diagnostic   => Truncate
                          (Value  => Result.Failure.Diagnostic,
                           Length => Buffer_Size - Spawn_Overhead)));
               when Spawn.Protocol.Request_Rejected =>
                  return
                    (Kind       => Spawn.Protocol.Request_Rejected,
                     Diagnostic => Truncate
                       (Value  => Result.Diagnostic,
                        Length => Buffer_Size - Basic_Overhead));
               when Spawn.Protocol.Protocol_Failed =>
                  return
                    (Kind       => Spawn.Protocol.Protocol_Failed,
                     Diagnostic => Truncate
                       (Value  => Result.Diagnostic,
                        Length => Buffer_Size - Basic_Overhead));
               when others =>
                  return Result;
            end case;
         end Bound_Result_Diagnostic;

         -------------------------------------------------------------------

         procedure Dispatch_Frame
           (Frame : Ada.Streams.Stream_Element_Array)
         is
            Header : Spawn.Protocol.Header_Type;
         begin
            Spawn.Protocol.Decode_Header
              (Data         => Frame
                 (Frame'First .. Frame'First
                  + Spawn.Protocol.Header_Size - 1),
               Active_Bound => Buffer_Size,
               Header       => Header);
            case Header.Kind is
               when Spawn.Protocol.Shell_Request =>
                  Handle_Shell_Request (Frame => Frame);
               when Spawn.Protocol.Exec_Request =>
                  Handle_Exec_Request (Frame => Frame);
               when Spawn.Protocol.Result_Message =>
                  raise Spawn.Protocol.Protocol_Error with
                    "request used result message kind";
            end case;
         end Dispatch_Frame;

         -------------------------------------------------------------------

         procedure Execute_And_Reply
           (Request : Spawn_Manager_Processes.Execution_Request)
         is
            Result : constant Spawn_Manager_Processes.Execution_Result
              := Spawn_Manager_Processes.Execute (Request => Request);
         begin
            pragma Debug
              (Logger.Log_File
                 ("Command result: "
                    & Spawn_Manager_Processes.Diagnostic (Result)));
            Send_Reply (Result => To_Protocol_Result (Result));
         end Execute_And_Reply;

         -------------------------------------------------------------------

         procedure Handle_Exec_Request
           (Frame : Ada.Streams.Stream_Element_Array)
         is
            Wire_Request : Spawn.Protocol.Exec_Request_Type;
         begin
            Spawn.Protocol.Decode_Exec_Request
              (Data         => Frame,
               Active_Bound => Buffer_Size,
               Request      => Wire_Request);
            pragma Debug
              (Logger.Log_File ("Structured exec request received:"));
            pragma Debug
              (Logger.Log_File
                 ("- EXE  [" & To_String (Wire_Request.Executable) & "]"));
            pragma Debug
              (Logger.Log_File
                 ("- ARGC [" & Wire_Request.Arguments.Length'Image & "]"));
            pragma Debug
              (Logger.Log_File
                 ("- ENVC [" & Wire_Request.Environment.Length'Image & "]"));
            Execute_And_Reply
              (Request => Spawn_Manager_Processes.Create_Exec_Request
                 (Request => Wire_Request));
         end Handle_Exec_Request;

         -------------------------------------------------------------------

         procedure Handle_Shell_Request
           (Frame : Ada.Streams.Stream_Element_Array)
         is
            Wire_Request : Spawn.Protocol.Shell_Request_Type;
         begin
            Spawn.Protocol.Decode_Shell_Request
              (Data         => Frame,
               Active_Bound => Buffer_Size,
               Request      => Wire_Request);
            pragma Debug (Logger.Log_File ("Shell request received:"));
            pragma Debug
              (Logger.Log_File
                 ("- CMD  [" & To_String (Wire_Request.Command) & "]"));
            pragma Debug
              (Logger.Log_File
                 ("- DIR  [" & To_String (Wire_Request.Directory) & "]"));
            Execute_And_Reply
              (Request => Spawn_Manager_Processes.Create_Shell_Request
                 (Command   => To_String (Wire_Request.Command),
                  Directory => To_String (Wire_Request.Directory),
                  Timeout   => Wire_Request.Timeout));
         end Handle_Shell_Request;

         -------------------------------------------------------------------

         procedure Send_Reply (Result : Spawn.Protocol.Result_Type)
         is
            Bounded_Result : constant Spawn.Protocol.Result_Type
              := Bound_Result_Diagnostic (Result => Result);
            Length : constant Positive := Spawn.Protocol.Result_Frame_Length
              (Result       => Bounded_Result,
               Active_Bound => Buffer_Size);
            Data : Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Length));
         begin
            Spawn.Protocol.Encode_Result
              (Result       => Bounded_Result,
               Active_Bound => Buffer_Size,
               Data         => Data);
            Spawn.Transport.Send_Frame
              (Descriptor => Connection.Get_Socket,
               Data       => Data);
            pragma Debug
              (Logger.Log_File
                 ("Result sent [" & Bounded_Result.Kind'Image & "]"));
         end Send_Reply;

         -------------------------------------------------------------------

         procedure Send_Reply_Protocol_Failure (Diagnostic : String)
         is
         begin
            Send_Reply
              (Result =>
                 (Kind       => Spawn.Protocol.Protocol_Failed,
                  Diagnostic => To_Unbounded_String (Diagnostic)));
         exception
            when others =>
               --  The original protocol or transport failure owns the
               --  connection. There is no second channel for a reply error.
               null;
         end Send_Reply_Protocol_Failure;

         -------------------------------------------------------------------

         procedure Serve_Connection
         is
         begin
            Main :
            loop
               begin
                  pragma Debug (Logger.Log_File ("Waiting for data"));
                  declare
                     Frame : constant Ada.Streams.Stream_Element_Array
                       := Spawn.Transport.Receive_Frame
                         (Descriptor   => Connection.Get_Socket,
                          Active_Bound => Buffer_Size);
                  begin
                     pragma Debug
                       (Logger.Log_File
                          ("Received" & Frame'Length'Img & " byte(s)"));
                     Dispatch_Frame (Frame => Frame);
                  end;
               exception
                  when E : Spawn.Protocol.Request_Error =>
                     pragma Debug (Logger.Log_File ("Request rejected:"));
                     pragma Debug
                       (Logger.Log_File
                          (Ada.Exceptions.Exception_Information (E)));
                     Send_Reply
                       (Result =>
                          (Kind       => Spawn.Protocol.Request_Rejected,
                           Diagnostic => To_Unbounded_String
                             (Ada.Exceptions.Exception_Message (E))));
                  when Spawn.Transport.Peer_Closed =>
                     exit Main;
                  when E : Spawn.Protocol.Protocol_Error
                     | Spawn.Transport.Extra_Data
                     | Spawn.Transport.Transport_Timeout =>
                     pragma Debug (Logger.Log_File ("Protocol failure:"));
                     pragma Debug
                       (Logger.Log_File
                          (Ada.Exceptions.Exception_Information (E)));
                     Send_Reply_Protocol_Failure
                       (Diagnostic => Ada.Exceptions.Exception_Message (E));
                     exit Main;
                  when E : others =>
                     pragma Debug
                       (Logger.Log_File ("Internal manager failure:"));
                     pragma Debug
                       (Logger.Log_File
                          (Ada.Exceptions.Exception_Information (E)));
                     Send_Reply_Protocol_Failure
                       (Diagnostic => "internal manager failure");
                     exit Main;
               end;
            end loop Main;
         end Serve_Connection;

      begin
         Listener.Bind
           (Path => Anet.Sockets.Unix.Path_Type (Socket_Path));
         pragma Debug
           (Logger.Log_File ("Listening on socket " & Socket_Path));
         Listener.Listen;

         Listener.Accept_Connection (New_Socket => Connection);
         Spawn.Transport.Set_Close_On_Exec
           (Descriptor => Connection.Get_Socket);
         Connection.Set_Nonblocking_Mode;
         pragma Debug (Logger.Log_File ("Connection established"));

         Serve_Connection;

         pragma Debug (Logger.Log_File ("Shutting down"));
         Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Success);
      end;
   end Run_Server;

   -------------------------------------------------------------------------

   function To_Protocol_Result
     (Result : Spawn_Manager_Processes.Execution_Result)
      return Spawn.Protocol.Result_Type
   is
   begin
      case Result.Kind is
         when Spawn_Manager_Processes.Exited =>
            return
              (Kind        => Spawn.Protocol.Exited,
               Exit_Status => Interfaces.Unsigned_32 (Result.Exit_Status));
         when Spawn_Manager_Processes.Signaled =>
            return
              (Kind          => Spawn.Protocol.Signaled,
               Signal_Number => Interfaces.Unsigned_16
                 (Result.Signal_Number));
         when Spawn_Manager_Processes.Timed_Out =>
            return (Kind => Spawn.Protocol.Timed_Out);
         when Spawn_Manager_Processes.Spawn_Failed
            | Spawn_Manager_Processes.Internal_Error =>
            --  The protocol deliberately has one execution-boundary failure
            --  alternative. Stage and errno retain the actionable failure
            --  point; the internal-versus-spawn classification is not public.
            return
              (Kind    => Spawn.Protocol.Spawn_Failed,
               Failure =>
                 (Stage => To_Protocol_Stage (Result.Stage),
                  Error_Number => Interfaces.Unsigned_32
                    (Result.Error_Number),
                  Diagnostic => To_Unbounded_String
                    (Spawn_Manager_Processes.Diagnostic (Result))));
      end case;
   end To_Protocol_Result;

   -------------------------------------------------------------------------

   function To_Protocol_Stage
     (Stage : Spawn_Manager_Processes.Failure_Stage)
      return Spawn.Protocol.Failure_Stage
   is
   begin
      case Stage is
         when Spawn_Manager_Processes.No_Failure =>
            return Spawn.Protocol.No_Failure;
         when Spawn_Manager_Processes.Enable_Subreaper =>
            return Spawn.Protocol.Enable_Subreaper;
         when Spawn_Manager_Processes.Create_Error_Pipe =>
            return Spawn.Protocol.Create_Error_Pipe;
         when Spawn_Manager_Processes.Fork_Child =>
            return Spawn.Protocol.Fork_Child;
         when Spawn_Manager_Processes.Process_Group =>
            return Spawn.Protocol.Process_Group;
         when Spawn_Manager_Processes.Parent_Death =>
            return Spawn.Protocol.Parent_Death;
         when Spawn_Manager_Processes.Open_Stdin =>
            return Spawn.Protocol.Open_Stdin;
         when Spawn_Manager_Processes.Open_Stdout =>
            return Spawn.Protocol.Open_Stdout;
         when Spawn_Manager_Processes.Open_Stderr =>
            return Spawn.Protocol.Open_Stderr;
         when Spawn_Manager_Processes.Duplicate_Stdin =>
            return Spawn.Protocol.Duplicate_Stdin;
         when Spawn_Manager_Processes.Duplicate_Stdout =>
            return Spawn.Protocol.Duplicate_Stdout;
         when Spawn_Manager_Processes.Duplicate_Stderr =>
            return Spawn.Protocol.Duplicate_Stderr;
         when Spawn_Manager_Processes.Change_Directory =>
            return Spawn.Protocol.Change_Directory;
         when Spawn_Manager_Processes.Reset_Signals =>
            return Spawn.Protocol.Reset_Signals;
         when Spawn_Manager_Processes.Close_Descriptors =>
            return Spawn.Protocol.Close_Descriptors;
         when Spawn_Manager_Processes.Exec_Target =>
            return Spawn.Protocol.Exec_Target;
         when Spawn_Manager_Processes.Wait_Child =>
            return Spawn.Protocol.Wait_Child;
         when Spawn_Manager_Processes.Terminate_Group =>
            return Spawn.Protocol.Terminate_Group;
      end case;
   end To_Protocol_Stage;

begin
   if Ada.Command_Line.Argument_Count /= 2 then
      Print_Usage;
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
      return;
   end if;

   declare
      Buffer_Size : constant Positive
        := Positive'Value (Ada.Command_Line.Argument (1));
      Socket_Path : constant String := Ada.Command_Line.Argument (2);
   begin
      Run_Server
        (Buffer_Size => Buffer_Size,
         Socket_Path => Socket_Path);
   end;

exception
   when E : others =>
      pragma Debug (Logger.Log_File ("Unhandled exception:"));
      pragma Debug
        (Logger.Log_File (Ada.Exceptions.Exception_Information (E)));
      raise;
end Spawn_Manager;
