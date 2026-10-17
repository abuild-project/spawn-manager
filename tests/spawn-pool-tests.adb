--
--  Process Spawn Manager
--
--  Copyright (C) 2012-2016 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012-2016 secunet Security Networks AG
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
with Ada.Exceptions;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;

with Interfaces;
with Interfaces.C;
with Interfaces.C.Strings;

with Anet.OS;
with Anet.Util;

with GNAT.Expect;

package body Spawn.Pool.Tests is

   package C renames Interfaces.C;
   package CS renames Interfaces.C.Strings;

   use Ahven;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type C.int;
   use type CS.chars_ptr;
   use type Spawn.Protocol.Failure_Stage;
   use type Spawn.Protocol.Result_Kind;

   function Block_Test_Signal return Interfaces.C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_test_block_signal";
   --  Save the caller mask and block one test signal before manager startup.

   function Restore_Test_Signal_Mask return Interfaces.C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_test_restore_signal_mask";
   --  Restore the signal mask saved by Block_Test_Signal.

   Manager_Path : constant String
     := Ada.Directories.Full_Name (Name => "obj/spawn_manager");
   Protocol_Failure_Manager_Path : constant String
     := Ada.Directories.Full_Name (Name => "obj/protocol_failure_manager");

   function C_Directory_Mode (Path : CS.chars_ptr) return C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_test_directory_mode";
   --  Return the permission bits of one test directory through the C fixture.

   function Directory_Path return CS.chars_ptr
     with Import,
          Convention    => C,
          External_Name => "spawn_test_directory_path";
   --  Return the path recorded by the directory-ownership fixtures.

   procedure Collide_Next_Directory (Enabled : C.int)
     with Import,
          Convention    => C,
          External_Name => "spawn_test_collide_next_directory";
   --  Make the next mkdir leave a foreign directory and report a collision.

   procedure Fail_Next_Chmod (Enabled : C.int)
     with Import,
          Convention    => C,
          External_Name => "spawn_test_fail_next_chmod";
   --  Make the next chmod fail after mkdir has transferred ownership.

   task type Executor is
      entry Call;
      entry Done (Success : out Boolean);
   end Executor;
   --  Task used in parallel tests.

   task body Executor is
      Got_Exception : Boolean := False;
   begin
      accept Call;

      begin
         Spawn.Pool.Execute (Command => "/bin/true");

      exception
         when E : others =>
            Ada.Text_IO.Put_Line
              (Ada.Exceptions.Exception_Information (X => E));
            Got_Exception := True;
      end;

      accept Done (Success : out Boolean) do
         Success := not Got_Exception;
      end Done;
   end Executor;

   Test_Buffer : Ada.Strings.Unbounded.Unbounded_String;

   procedure Test_Log (Msg : String);
   --  Append message to test buffer.

   Test_Log_Exception : exception;

   Cleanup_Log_Attempts : Natural := 0;
   --  Count injected cleanup diagnostics so the failure test is non-vacuous.

   procedure Test_Log_Error (Msg : String);
   --  Just raises a test exception.

   procedure Cleanup_Log_Error (Msg : String);
   --  Raise only for a diagnostic emitted after manager interruption.

   Ready_Log_Attempts : Natural := 0;
   --  Count injected failures after a manager enters the pool.

   Ready_Log_Path : constant String := "obj/ready-log-reuse.out";
   Ready_Log_File : Ada.Text_IO.File_Type;
   --  Hold one descriptor allocated between local and pool cleanup.

   procedure Raise_Delete_Error (Filename : String);
   --  Raise a deterministic socket deletion error.

   procedure Ready_Log_Error (Msg : String);
   --  Raise when initialization reports a manager as ready for use.

   -------------------------------------------------------------------------

   procedure Caller_Abort_Releases_Lease
   is
      protected type Start_Signal is
         entry Wait;
         procedure Mark;
         --  Release Wait after the worker has acquired its manager lease.
      private
         Started : Boolean := False;
      end Start_Signal;

      protected body Start_Signal is
         procedure Mark
         is
         begin
            Started := True;
         end Mark;

         entry Wait when Started
         is
         begin
            null;
         end Wait;
      end Start_Signal;

      Signal : Start_Signal;

      procedure Mark_Manager (Pid : GNAT.Expect.Process_Descriptor);
      --  Mark lease acquisition and hold the worker at an abort completion.

      procedure Mark_Manager (Pid : GNAT.Expect.Process_Descriptor)
      is
         pragma Unreferenced (Pid);
      begin
         Signal.Mark;
         --  Delay is an abort completion point after the manager lease has
         --  been acquired but before a request can reach the socket.
         delay 60.0;
      end Mark_Manager;

      task Worker is
         entry Start;
      end Worker;

      task body Worker is
      begin
         accept Start;
         Spawn.Pool.Execute
           (Command   => "/bin/true",
            Pid_Setup => Mark_Manager'Access);
      end Worker;

      Initialized : Boolean := False;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Worker.Start;
      Signal.Wait;

      --  Abort after Get_Socket but before Send_Receive. Ordinary exception
      --  handlers do not run for this asynchronous transfer of control.
      abort Worker;

      --  Wait for finalization before Cleanup starts cancelling managers.
      --  Otherwise Cleanup itself can wake the worker's socket operation and
      --  let the normal release path mask a lease stranded by task abort.
      while not Worker'Terminated loop
         delay 0.010;
      end loop;

      begin
         Spawn.Pool.Execute (Command => "/bin/true");
         Fail (Message => "aborted lease did not poison the pool");
      exception
         when E : Spawn.Pool.Pool_Error =>
            Assert
              (Condition => Ada.Exceptions.Exception_Message (X => E)
                 = "spawn manager pool has failed",
               Message   => "aborted-lease pool diagnostic differs");
      end;

      Spawn.Pool.Cleanup;
      Initialized := False;

      --  Cleanup must leave the package ready for the next Abuild run.
      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         raise;
   end Caller_Abort_Releases_Lease;

   -------------------------------------------------------------------------

   procedure Cleanup_Log_Error (Msg : String)
   is
   begin
      if Ada.Strings.Fixed.Index (Source  => Msg,
                                  Pattern => "terminated") > 0
        or else Ada.Strings.Fixed.Index
          (Source  => Msg,
           Pattern => "Timeout occurred") > 0
      then
         Cleanup_Log_Attempts := Cleanup_Log_Attempts + 1;
         raise Test_Log_Exception;
      end if;
   end Cleanup_Log_Error;

   -------------------------------------------------------------------------

   procedure Cleanup_Relative_Socket
   is
      use Ada.Directories;

      Dir               : constant String := "obj/relative-socket-"
        & Anet.Util.Random_String (Len => 8);
      Log_Prefix        : constant String := "Forked manager ";
      Pool_Directory    : Unbounded_String;
      Socket_Path       : Unbounded_String;
      Original_Dir      : constant String := Current_Directory;
      Initialized       : Boolean := False;
      Directory_Changed : Boolean := False;

      procedure Remove_Test_Directory;
      --  Remove the relative socket fixture after restoring the caller cwd.

      procedure Remove_Test_Directory
      is
      begin
         if Exists (Name => Dir) then
            Delete_Tree (Directory => Dir);
         end if;
      end Remove_Test_Directory;
   begin
      Create_Directory (New_Directory => Dir);
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Socket_Dir   => Dir,
                       Log          => Test_Log'Access);
      Initialized := True;

      declare
         Log_Data      : constant String := To_String (Test_Buffer);
         Prefix_First  : Natural;
         Address_First : Natural;
         Newline       : Natural;
      begin
         Prefix_First := Ada.Strings.Fixed.Index
           (Source  => Log_Data,
            Pattern => Log_Prefix);
         Assert (Condition => Prefix_First > 0,
                 Message   => "Manager socket address not logged");
         Address_First := Prefix_First + Log_Prefix'Length;
         Newline := Ada.Strings.Fixed.Index
           (Source  => Log_Data,
            Pattern => (1 => ASCII.LF),
            From    => Address_First);
         Assert (Condition => Newline > Address_First,
                 Message   => "Manager socket address not terminated");
         Socket_Path := To_Unbounded_String
           (Log_Data (Address_First .. Newline - 1));
         Assert
           (Condition => Element (Source => Socket_Path, Index => 1) /= '/',
            Message   => "Relative manager socket became absolute");
         Assert
           (Condition => Ada.Strings.Fixed.Index
              (Source  => To_String (Socket_Path),
               Pattern => Dir & "/.sp-") = 1,
            Message   => "Relative manager socket lost its short spelling");
         Pool_Directory := To_Unbounded_String
           (Containing_Directory (Name => To_String (Socket_Path)));
         declare
            Path : CS.chars_ptr := CS.New_String (To_String (Pool_Directory));
            Mode : C.int;
         begin
            Mode := C_Directory_Mode (Path => Path);
            CS.Free (Path);
            Assert (Condition => Mode = 8#700#,
                    Message   => "Pool socket directory is not mode 0700");
         exception
            when others =>
               if Path /= CS.Null_Ptr then
                  CS.Free (Path);
               end if;
               raise;
         end;
      end;

      --  The manager changes its cwd for the command. The parent then changes
      --  its cwd before cleanup. A relative socket path must still be removed
      --  from the directory where it was bound during Init.
      Spawn.Pool.Execute (Command   => "/bin/true",
                          Directory => "/tmp");
      Set_Directory (Directory => "/tmp");
      Directory_Changed := True;
      Spawn.Pool.Cleanup;
      Initialized := False;
      Set_Directory (Directory => Original_Dir);
      Directory_Changed := False;

      begin
         Anet.OS.Delete_File
           (Filename       => To_String (Socket_Path),
            Ignore_Missing => False);
         Fail (Message => "Relative manager socket was not removed: "
               & To_String (Socket_Path));
      exception
         when Anet.OS.IO_Error => null;
      end;
      Assert (Condition => not Exists (Name => To_String (Pool_Directory)),
              Message   => "Private pool socket directory was not removed");
      Test_Buffer := Null_Unbounded_String;
      Remove_Test_Directory;

   exception
      when others =>
         Test_Buffer := Null_Unbounded_String;
         if Directory_Changed then
            Set_Directory (Directory => Original_Dir);
            Directory_Changed := False;
         end if;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Remove_Test_Directory;
         raise;
   end Cleanup_Relative_Socket;

   -------------------------------------------------------------------------

   procedure Cleanup_Removed_Pool_Directory
   is
      use Ada.Directories;

      Dir : constant String := "obj/missing-pool-directory-"
        & Anet.Util.Random_String (Len => 8);
      Error_Prefix : constant String
        := "Unable to remove private socket directory '";
      Initialized : Boolean := False;
   begin
      Create_Directory (New_Directory => Dir);
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init
        (Manager_Path => Manager_Path,
         Socket_Dir   => Dir,
         Log          => Test_Log'Access);
      Initialized := True;

      --  Abuild removes its complete temporary tree through the final manager
      --  request before shutting the pool down. Model that exact ordering.
      Spawn.Pool.Execute (Command => "/bin/rm -rf -- " & Dir);
      Spawn.Pool.Cleanup;
      Initialized := False;

      Assert
        (Condition => Ada.Strings.Fixed.Index
           (Source  => To_String (Test_Buffer),
            Pattern => Error_Prefix) = 0,
         Message   => "missing private socket directory was reported");
      Test_Buffer := Null_Unbounded_String;
   exception
      when others =>
         if Initialized then
            begin
               Spawn.Pool.Cleanup;
            exception
               when others => null;
            end;
         end if;
         if Exists (Name => Dir) then
            Delete_Tree (Directory => Dir);
         end if;
         Test_Buffer := Null_Unbounded_String;
         raise;
   end Cleanup_Removed_Pool_Directory;

   -------------------------------------------------------------------------

   procedure Cleanup_Socket_After_Delete_Error
   is
      use Ada.Directories;

      Dir : constant String := "obj/delete-error-"
        & Anet.Util.Random_String (Len => 8);
      Error_Prefix : constant String := "Unable to remove manager socket '"
        & Current_Directory & "/" & Dir & "/";

      Initialized : Boolean := False;
      Socket_Paths : array (1 .. 2) of Unbounded_String;

      procedure Capture_Socket_Paths;
      --  Preserve the two logged paths before injected deletion leaves them.

      procedure Capture_Socket_Paths
      is
         Prefix : constant String := "Forked manager ";
         Source : constant String := To_String (Test_Buffer);
         Next   : Positive := Source'First;
      begin
         for Path of Socket_Paths loop
            declare
               First : constant Natural := Ada.Strings.Fixed.Index
                 (Source  => Source,
                  Pattern => Prefix,
                  From    => Next);
               Last : constant Natural := Ada.Strings.Fixed.Index
                 (Source  => Source,
                  Pattern => (1 => ASCII.LF),
                  From    => First + Prefix'Length);
            begin
               Assert
                 (Condition => First > 0 and then Last > First,
                  Message   => "manager socket path was not logged");
               Path := To_Unbounded_String
                 (Source (First + Prefix'Length .. Last - 1));
               Next := Last + 1;
            end;
         end loop;
      end Capture_Socket_Paths;

      procedure Remove_Test_Directory;
      --  Remove the socket-deletion fixture after pool cleanup completes.

      procedure Remove_Test_Directory
      is
      begin
         for Path of Socket_Paths loop
            if Path /= Null_Unbounded_String then
               begin
                  Anet.OS.Delete_File (Filename => To_String (Path));
               exception
                  when Anet.OS.IO_Error => null;
               end;
            end if;
         end loop;
         if Exists (Name => Dir) then
            Delete_Tree (Directory => Dir);
         end if;
      end Remove_Test_Directory;
   begin
      Create_Directory (New_Directory => Dir);
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init (Manager_Path  => Manager_Path,
                       Manager_Count => 2,
                       Socket_Dir    => Dir,
                       Log           => Test_Log'Access);
      Initialized := True;
      Capture_Socket_Paths;

      Socket_File_Delete := Raise_Delete_Error'Access;

      Spawn.Pool.Cleanup;
      Initialized := False;
      Socket_File_Delete := Delete_Socket_File'Access;

      Assert
        (Condition => Ada.Strings.Fixed.Count
           (Source  => To_String (Test_Buffer),
            Pattern => Error_Prefix) = 2,
         Message   => "Cleanup did not report both socket delete errors");

      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Cleanup;
      Assert (Condition => Length (Test_Buffer) = 0,
              Message   => "Socket store was not cleared after delete errors");

      Remove_Test_Directory;

   exception
      when others =>
         Socket_File_Delete := Delete_Socket_File'Access;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Test_Buffer := Null_Unbounded_String;
         Remove_Test_Directory;
         raise;
   end Cleanup_Socket_After_Delete_Error;

   -------------------------------------------------------------------------

   procedure Cleanup_Survives_Log_Error
   is
      Initialized : Boolean := False;
   begin
      Cleanup_Log_Attempts := 0;
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Cleanup_Log_Error'Access);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Assert (Condition => Cleanup_Log_Attempts > 0,
              Message   => "cleanup log failure was not injected");

      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Cleanup_Log_Attempts := 0;

   exception
      when others =>
         if Initialized then
            begin
               Spawn.Pool.Cleanup;
            exception
               when others => null;
            end;
         end if;
         Cleanup_Log_Attempts := 0;
         raise;
   end Cleanup_Survives_Log_Error;

   -------------------------------------------------------------------------

   procedure Command_Timeout
   is
      use Ada.Real_Time;

      Start : Time;
      Span  : Time_Span := To_Time_Span (D => 100.0);
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);

      begin
         Start := Clock;

         --  Command would run for 60 seconds but it should timeout after 50
         --  milliseconds.

         Spawn.Pool.Execute (Command => "/bin/sleep 60",
                             Timeout => 50);
         Fail (Message => "Failure expected");

      exception
         when Spawn.Pool.Command_Failed => Span := Clock - Start;
      end;

      Spawn.Pool.Cleanup;

      Assert (Condition => Span >= Milliseconds (MS => 50),
              Message   => "Timeout not >= 50ms");

      --  Take heavy system load into account; allow up to 1s as upper
      --  threshold

      Assert (Condition => Span < Seconds (S => 1),
              Message   => "Timeout not < 1s");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Command_Timeout;

   -------------------------------------------------------------------------

   procedure Connect_Retry_On_Refused
   is
      S_Server : Anet.Sockets.Unix.TCP_Socket_Type;
      S_Client : Socket_Handle
        := new Anet.Sockets.Unix.TCP_Socket_Type;
      Path     : constant Anet.Sockets.Unix.Path_Type
        := Anet.Sockets.Unix.Path_Type
          ("/tmp/spawn.retry-" & Anet.Util.Random_String (Len => 12));

      procedure Cleanup;
      --  Close both retry sockets and restore the pool logger hook.

      procedure Cleanup
      is
      begin
         S_Client.Close;
         S_Server.Close;
         Free (X => S_Client);
         Spawn.Pool.Cleanup;
         Pool_Log := null;
      end Cleanup;
   begin
      Pool_Log := Ada.Text_IO.Put_Line'Access;

      S_Server.Init;
      S_Client.Init;

      --  Socket error, but not connection refused.

      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Anet.Socket_Error => null;
      end;

      S_Server.Bind (Path => Path);

      --  Connection refused error.

      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Connection_Refused => null;
      end;

      --  Reconnect succesful.

      declare
         Listen_Exception : Boolean := False;

         task Listen;
         task body Listen
         is
         begin
            delay 2.0;
            S_Server.Listen;

         exception
            when E : others =>
               Ada.Text_IO.Put_Line
                 (Ada.Exceptions.Exception_Information (X => E));
               Listen_Exception := True;
         end Listen;
      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 6);

         Assert (Condition => not Listen_Exception,
                 Message   => "Exception in listener");

         if not Listen'Terminated then
            abort Listen;
         end if;

      exception
         when others =>
            if not Listen'Terminated then
               abort Listen;
            end if;
            Cleanup;
            raise;
      end;

      Cleanup;

   exception
      when others =>
         Cleanup;
         raise;
   end Connect_Retry_On_Refused;

   -------------------------------------------------------------------------

   procedure Directory_Chmod_Failure_Cleanup
   is
      use Ada.Directories;

      Root : constant String := "obj/pool-chmod-failure-"
        & Anet.Util.Random_String (Len => 8);
      Owned_Path  : Unbounded_String;
      Initialized : Boolean := False;
   begin
      Create_Directory (New_Directory => Root);
      Fail_Next_Chmod (Enabled => 1);
      begin
         Spawn.Pool.Init
           (Manager_Path => Manager_Path,
            Socket_Dir   => Root);
         Initialized := True;
         Fail (Message => "synthetic chmod failure was accepted");
      exception
         when Spawn.Pool.Pool_Error => null;
      end;
      Fail_Next_Chmod (Enabled => 0);

      Owned_Path := To_Unbounded_String (CS.Value (Directory_Path));
      Assert (Condition => Length (Owned_Path) > 0,
              Message   => "chmod fixture did not record its path");
      Assert (Condition => not Exists (Name => To_String (Owned_Path)),
              Message   => "owned directory survived chmod failure");
      Delete_Tree (Directory => Root);

      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
   exception
      when others =>
         Fail_Next_Chmod (Enabled => 0);
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         if Exists (Name => Root) then
            Delete_Tree (Directory => Root);
         end if;
         raise;
   end Directory_Chmod_Failure_Cleanup;

   -------------------------------------------------------------------------

   procedure Directory_Collision_Ownership
   is
      use Ada.Directories;

      Root : constant String := "obj/pool-collision-"
        & Anet.Util.Random_String (Len => 8);
      Foreign_Path : Unbounded_String;
      Initialized  : Boolean := False;

      procedure Remove_Root;
      --  Remove the complete collision fixture when it still exists.

      procedure Remove_Root
      is
      begin
         if Exists (Name => Root) then
            Delete_Tree (Directory => Root);
         end if;
      end Remove_Root;
   begin
      Create_Directory (New_Directory => Root);
      Collide_Next_Directory (Enabled => 1);
      begin
         Spawn.Pool.Init
           (Manager_Path => Manager_Path,
            Socket_Dir   => Root);
         Initialized := True;
         Fail (Message => "synthetic directory collision was accepted");
      exception
         when Spawn.Pool.Pool_Error => null;
      end;
      Collide_Next_Directory (Enabled => 0);

      Foreign_Path := To_Unbounded_String (CS.Value (Directory_Path));
      Assert (Condition => Length (Foreign_Path) > 0,
              Message   => "collision fixture did not record its path");
      Assert (Condition => Exists (Name => To_String (Foreign_Path)),
              Message   => "foreign collision directory was removed");
      Remove_Root;

      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
   exception
      when others =>
         Collide_Next_Directory (Enabled => 0);
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Remove_Root;
         raise;
   end Directory_Collision_Ownership;

   -------------------------------------------------------------------------

   procedure Duplicate_Init
   is
   begin
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Test_Log'Access);
      begin
         Spawn.Pool.Init
           (Manager_Path => Manager_Path,
            Buffer_Size  => Spawn.Protocol.Header_Size,
            Log          => Test_Log_Error'Access);
         Fail (Message => "duplicate pool initialization accepted");
      exception
         when Spawn.Pool.Pool_Error => null;
      end;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Test_Buffer := Null_Unbounded_String;
   exception
      when others =>
         Spawn.Pool.Cleanup;
         Test_Buffer := Null_Unbounded_String;
         raise;
   end Duplicate_Init;

   -------------------------------------------------------------------------

   procedure Execute_Bin_False
   is
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => "/bin/false");
      Spawn.Pool.Cleanup;
      Fail (Message => "Exception expected");

   exception
      when Spawn.Pool.Command_Failed =>
         Spawn.Pool.Cleanup;
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Bin_False;

   -------------------------------------------------------------------------

   procedure Execute_Bin_True
   is
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Bin_True;

   -------------------------------------------------------------------------

   procedure Execute_Complex_Command
   is
      File : constant String := "obj/tmp.dat";
      Cmd  : constant String := "dd if=/dev/zero bs=1 count=1 of=" & File
        & " > /dev/null 2>&1";
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => Cmd);
      Spawn.Pool.Cleanup;

      Assert (Condition => Ada.Directories.Exists (Name => File),
              Message   => "File not found: " & File);
      Ada.Directories.Delete_File (Name => File);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         Ada.Directories.Delete_File (Name => File);
         raise;
   end Execute_Complex_Command;

   -------------------------------------------------------------------------

   procedure Execute_Merged_Streams
   is
      Root : constant String := Ada.Directories.Current_Directory
        & "/obj/shared ' output-" & Anet.Util.Random_String (Len => 8);
      Output_Path : constant String := Root & "/output";
      Created : Boolean := False;
      Request : Spawn.Protocol.Exec_Request_Type;
      Result : Spawn.Protocol.Result_Type;

      function Read_Log (Path : String) return String;
      --  Read log lines and normalize each line ending to LF.

      procedure Cleanup;
      --  Shut down managers before removing only this test's owned directory.

      procedure Cleanup
      is
      begin
         Spawn.Pool.Cleanup;
         if Created and then Ada.Directories.Exists (Root) then
            Ada.Directories.Delete_Tree (Root);
         end if;
      end Cleanup;

      function Read_Log (Path : String) return String
      is
         File : Ada.Text_IO.File_Type;
         Text : Unbounded_String;
      begin
         Ada.Text_IO.Open
           (File, Ada.Text_IO.In_File, Path, Form => "shared=no");
         while not Ada.Text_IO.End_Of_File (File) loop
            Append (Text, Ada.Text_IO.Get_Line (File) & ASCII.LF);
         end loop;
         Ada.Text_IO.Close (File);
         return To_String (Text);
      exception
         when others =>
            if Ada.Text_IO.Is_Open (File) then
               Ada.Text_IO.Close (File);
            end if;
            raise;
      end Read_Log;
   begin
      Ada.Directories.Create_Directory (Root);
      Created := True;
      Spawn.Pool.Init (Manager_Path => Manager_Path, Manager_Count => 2);
      Request.Executable := To_Unbounded_String ("/bin/sh");
      Request.Directory := To_Unbounded_String ("/");
      Request.Timeout := 2_000;
      Request.Arguments.Append ("-c");
      Request.Arguments.Append
        ("printf 'stdout\n'; printf 'stderr\n' >&2; printf 'after\n'; exit 7");
      Request.Standard_Error := (Mode => Spawn.Protocol.Merge_Stdout);
      Request.Standard_Output := (Mode => Spawn.Protocol.Merge_Stdout);
      Result := Spawn.Pool.Execute (Request);
      Assert (Result.Kind = Spawn.Protocol.Request_Rejected,
              "stdout self-reference was not rejected before dispatch");

      Request.Standard_Output :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Output_Path));
      Result := Spawn.Pool.Execute (Request);
      Assert (Result.Kind = Spawn.Protocol.Exited
                and then Result.Exit_Status = 7,
              "shared log changed exit status or prevented reuse");
      Assert (Read_Log (Output_Path)
                = "stdout" & ASCII.LF & "stderr" & ASCII.LF
                  & "after" & ASCII.LF,
              "shared log lost bytes or write order");

      Request.Standard_Output := (Mode => Spawn.Protocol.Null_Stream);
      Request.Arguments.Replace_Element
        (2, "test -c /proc/self/fd/1 && test /proc/self/fd/1 -ef /dev/null"
         & " && test -c /proc/self/fd/2"
         & " && test /proc/self/fd/2 -ef /dev/null || exit 99;"
         & " printf output; printf error >&2; exit 7");
      Result := Spawn.Pool.Execute (Request);
      Assert (Result.Kind = Spawn.Protocol.Exited
                and then Result.Exit_Status = 7,
              "shared null output did not connect both descriptors to null");

      Request.Standard_Output :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Root & "/missing/log"));
      Result := Spawn.Pool.Execute (Request);
      Assert (Result.Kind = Spawn.Protocol.Spawn_Failed
                and then Result.Failure.Stage = Spawn.Protocol.Open_Stdout,
              "shared sink open failure has the wrong stage");

      Request.Standard_Output :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Output_Path));
      Request.Arguments.Replace_Element
        (2, "printf 'before timeout\n' >&2; exec /bin/sleep 60");
      Request.Timeout := 1_000;
      Result := Spawn.Pool.Execute (Request);
      Assert (Result.Kind = Spawn.Protocol.Timed_Out,
              "shared log changed timeout classification");
      Assert (Read_Log (Output_Path) = "before timeout" & ASCII.LF,
              "timeout discarded the shared diagnostic");

      declare
         --  Root is immutable. Each caller owns its request and output; the
         --  child-side ready barrier requires both managers to be active.
         task type Writer is
            entry Start (Number : Positive);
            entry Join (Success : out Boolean);
         end Writer;

         task body Writer
         is
            Index : Positive := 1;
            Passed : Boolean := False;
         begin
            accept Start (Number : Positive) do
               Index := Number;
            end Start;
            declare
               Token : constant String := Ada.Strings.Fixed.Trim
                 (Index'Image, Ada.Strings.Both);
               Path : constant String := Root & "/parallel-" & Token;
               Child_Request : Spawn.Protocol.Exec_Request_Type;
               Child_Result : Spawn.Protocol.Result_Type;
            begin
               Child_Request.Executable := To_Unbounded_String ("/bin/sh");
               Child_Request.Directory := To_Unbounded_String ("/");
               Child_Request.Timeout := 2_000;
               Child_Request.Standard_Output :=
                 (Mode => Spawn.Protocol.Truncate_File,
                  Path => To_Unbounded_String (Path));
               Child_Request.Standard_Error :=
                 (Mode => Spawn.Protocol.Merge_Stdout);
               Child_Request.Arguments.Append ("-c");
               Child_Request.Arguments.Append
                 (": > ""$1/ready-$2""; while test ! -e ""$1/ready-1"""
                  & " || test ! -e ""$1/ready-2""; do /bin/sleep 0.001; done;"
                  & " printf 'out-%s\n' ""$2"";"
                  & " printf 'err-%s\n' ""$2"" >&2");
               Child_Request.Arguments.Append ("shared-fixture");
               Child_Request.Arguments.Append (Root);
               Child_Request.Arguments.Append (Token);
               Child_Result := Spawn.Pool.Execute (Child_Request);
               Passed := Child_Result.Kind = Spawn.Protocol.Exited
                 and then Child_Result.Exit_Status = 0
                 and then Read_Log (Path) = "out-" & Token & ASCII.LF
                   & "err-" & Token & ASCII.LF;
            exception
               when others => Passed := False;
            end;
            accept Join (Success : out Boolean) do
               Success := Passed;
            end Join;
         end Writer;

         Writers : array (1 .. 2) of Writer;
         Passed : Boolean;
         All_Passed : Boolean := True;
      begin
         for I in Writers'Range loop
            Writers (I).Start (I);
         end loop;
         for Worker of Writers loop
            Worker.Join (Passed);
            All_Passed := All_Passed and Passed;
         end loop;
         Assert (All_Passed, "parallel shared logs mixed or lost bytes");
      end;
      Cleanup;
   exception
      when others =>
         Cleanup;
         raise;
   end Execute_Merged_Streams;

   -------------------------------------------------------------------------

   procedure Execute_Nonexistent
   is
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);

      begin
         Spawn.Pool.Execute (Command => "nonexistent/binary");
         Spawn.Pool.Cleanup;
         Fail (Message => "Exception expected");

      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      --  Check if manager is still responding to requests.

      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Nonexistent;

   -------------------------------------------------------------------------

   procedure Execute_Nonterminating_Command
   is
      Got_Exception : Boolean := False;

      task Executor
      is
         entry Start;
      end Executor;

      task body Executor
      is
      begin
         accept Start;
         Spawn.Pool.Execute ("/bin/sleep 10000");

      exception
         when Spawn.Pool.Command_Failed => Got_Exception := True;
         when others                    => null;
      end Executor;

   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Executor.Start;

      delay 0.3;
      Spawn.Pool.Cleanup;

      delay 0.3;
      if not Executor'Terminated then
         abort Executor;
      end if;

      Assert (Condition => Got_Exception,
              Message   => "Exception expected");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if not Executor'Terminated then
            abort Executor;
         end if;
         raise;
   end Execute_Nonterminating_Command;

   -------------------------------------------------------------------------

   procedure Execute_Shell_Environment
   is
      package ENV renames Ada.Environment_Variables;

      Name        : constant String := "SPAWN_MANAGER_TEST_ENV";
      Original    : Unbounded_String;
      Was_Set     : constant Boolean := ENV.Exists (Name => Name);
      Initialized : Boolean := False;

      procedure Restore_Environment;
      --  Restore the caller environment after the manager snapshot test.

      procedure Restore_Environment
      is
      begin
         if Was_Set then
            ENV.Set (Name => Name, Value => To_String (Original));
         else
            ENV.Clear (Name => Name);
         end if;
      end Restore_Environment;
   begin
      if Was_Set then
         Original := To_Unbounded_String (ENV.Value (Name => Name));
      end if;
      ENV.Set (Name => Name, Value => "manager value");
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Initialized := True;

      --  Later caller mutation must not alter the already running manager.

      ENV.Set (Name => Name, Value => "caller value");
      Spawn.Pool.Execute
        (Command => "test ""$" & Name & """ = 'manager value'");

      Spawn.Pool.Cleanup;
      Initialized := False;
      Restore_Environment;

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Restore_Environment;
         raise;
   end Execute_Shell_Environment;

   -------------------------------------------------------------------------

   procedure Execute_Shell_Syntax
   is
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command => "test ""$(printf '%s' 'a b')"" = 'a b'"
         & " && test $((2 + 3)) -eq 5");

      begin
         Spawn.Pool.Execute (Command => "false | true");
         Fail (Message => "pipefail did not reject the pipeline");
      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      --  A normal command failure does not poison the legacy manager.

      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Shell_Syntax;

   -------------------------------------------------------------------------

   procedure Execute_Signal_Mask
   is
      Mask_Saved : Boolean := False;
   begin
      Assert
        (Condition => Block_Test_Signal = 0,
         Message   => "unable to prepare inherited signal mask");
      Mask_Saved := True;

      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command => "grep -Eq '^SigBlk:[[:space:]]+0+$' "
         & "/proc/self/status");
      Spawn.Pool.Cleanup;

      Assert
        (Condition => Restore_Test_Signal_Mask = 0,
         Message   => "unable to restore inherited signal mask");
      Mask_Saved := False;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Mask_Saved then
            Mask_Saved := Restore_Test_Signal_Mask /= 0;
         end if;
         raise;
   end Execute_Signal_Mask;

   -------------------------------------------------------------------------

   procedure Execute_Structured
   is
      Request : Spawn.Protocol.Exec_Request_Type;
      Result  : Spawn.Protocol.Result_Type;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Request.Executable := To_Unbounded_String ("/bin/true");
      Request.Directory := To_Unbounded_String ("/");
      Request.Standard_Output := (Mode => Spawn.Protocol.Null_Stream);
      Request.Standard_Error := (Mode => Spawn.Protocol.Null_Stream);
      Request.Timeout := -1;
      Result := Spawn.Pool.Execute (Request => Request);
      Assert
        (Condition => Result.Kind = Spawn.Protocol.Exited
           and then Result.Exit_Status = 0,
         Message   => "structured true result differs");

      Request.Executable := To_Unbounded_String ("/bin/false");
      Result := Spawn.Pool.Execute (Request => Request);
      Assert
        (Condition => Result.Kind = Spawn.Protocol.Exited
           and then Result.Exit_Status = 1,
         Message   => "structured false result differs");
      begin
         Spawn.Pool.Execute_Checked (Request => Request);
         Fail (Message => "checked structured failure accepted");
      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      Request.Executable := To_Unbounded_String
        ("/definitely/missing/structured-target");
      Result := Spawn.Pool.Execute (Request => Request);
      Assert
        (Condition => Result.Kind = Spawn.Protocol.Spawn_Failed
           and then Result.Failure.Stage = Spawn.Protocol.Exec_Target,
         Message   => "structured spawn failure differs");

      Request.Executable := To_Unbounded_String ("/bin/sleep");
      Request.Arguments.Append ("60");
      Request.Timeout := 50;
      Result := Spawn.Pool.Execute (Request => Request);
      Assert (Condition => Result.Kind = Spawn.Protocol.Timed_Out,
              Message   => "structured timeout result differs");

      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Structured;

   -------------------------------------------------------------------------

   procedure Execute_Structured_Environment
   is
      use Ada.Directories;

      Output_Path : constant String := Current_Directory
        & "/obj/structured-environment.out";

      procedure Run_And_Check (Value : String);
      --  Run env with only ONLY=Value and verify its complete visible state.

      procedure Run_And_Check (Value : String)
      is
         Output  : Ada.Text_IO.File_Type;
         Request : Spawn.Protocol.Exec_Request_Type;
         Result  : Spawn.Protocol.Result_Type;
      begin
         if Exists (Name => Output_Path) then
            Delete_File (Name => Output_Path);
         end if;
         Request.Executable := To_Unbounded_String ("/usr/bin/env");
         Request.Environment.Append
           ((Name  => To_Unbounded_String ("ONLY"),
             Value => To_Unbounded_String (Value)));
         Request.Directory := To_Unbounded_String (Current_Directory);
         Request.Standard_Output :=
           (Mode => Spawn.Protocol.Truncate_File,
            Path => To_Unbounded_String (Output_Path));
         Request.Standard_Error := (Mode => Spawn.Protocol.Null_Stream);
         Request.Timeout := 1_000;
         Result := Spawn.Pool.Execute (Request => Request);
         Assert
           (Condition => Result.Kind = Spawn.Protocol.Exited
              and then Result.Exit_Status = 0,
            Message   => "environment request failed");
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => Ada.Text_IO.Get_Line (File => Output)
              = "ONLY=" & Value,
            Message   => "replacement environment differs");
         Assert (Condition => Ada.Text_IO.End_Of_File (File => Output),
                 Message   => "replacement environment leaked entries");
         Ada.Text_IO.Close (File => Output);
         Delete_File (Name => Output_Path);

      exception
         when others =>
            if Ada.Text_IO.Is_Open (File => Output) then
               Ada.Text_IO.Close (File => Output);
            end if;
            if Exists (Name => Output_Path) then
               Delete_File (Name => Output_Path);
            end if;
            raise;
      end Run_And_Check;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Run_And_Check (Value => "first");

      declare
         Request : Spawn.Protocol.Exec_Request_Type;
         Result  : Spawn.Protocol.Result_Type;
      begin
         Request.Executable := To_Unbounded_String ("/bin/false");
         Request.Directory := To_Unbounded_String ("/");
         Request.Standard_Output := (Mode => Spawn.Protocol.Null_Stream);
         Request.Standard_Error := (Mode => Spawn.Protocol.Null_Stream);
         Request.Timeout := 1_000;
         Result := Spawn.Pool.Execute (Request => Request);
         Assert
           (Condition => Result.Kind = Spawn.Protocol.Exited
              and then Result.Exit_Status = 1,
            Message   => "intermediate failure result differs");

         Request.Executable := To_Unbounded_String
           ("/definitely/missing/environment-target");
         Result := Spawn.Pool.Execute (Request => Request);
         Assert (Condition => Result.Kind = Spawn.Protocol.Spawn_Failed,
                 Message   => "intermediate spawn failure differs");

         Request.Executable := To_Unbounded_String ("/bin/sleep");
         Request.Arguments.Append ("60");
         Request.Timeout := 50;
         Result := Spawn.Pool.Execute (Request => Request);
         Assert (Condition => Result.Kind = Spawn.Protocol.Timed_Out,
                 Message   => "intermediate timeout differs");
      end;

      Run_And_Check (Value => "second");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         if Exists (Name => Output_Path) then
            Delete_File (Name => Output_Path);
         end if;
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Structured_Environment;

   -------------------------------------------------------------------------

   procedure Execute_Working_Directories
   is
      use Ada.Directories;

      Root : constant String := "obj/directory-"
        & Anet.Util.Random_String (Len => 8);
      First_Directory  : constant String := Root & "/first";
      Second_Directory : constant String := Root & "/second";
      Missing_Directory : constant String := Root & "/missing";
      Output_Path : constant String := Current_Directory & "/" & Root
        & "/pwd.out";

      procedure Assert_Directory (Expected : String);
      --  Execute pwd in Expected and verify the child-visible directory.

      procedure Assert_Directory (Expected : String)
      is
         Output : Ada.Text_IO.File_Type;
      begin
         Spawn.Pool.Execute
           (Command   => "pwd > " & Output_Path,
            Directory => Expected);
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => Ada.Text_IO.Get_Line (File => Output) = Expected,
            Message   => "child working directory changed");
         Ada.Text_IO.Close (File => Output);

      exception
         when others =>
            if Ada.Text_IO.Is_Open (File => Output) then
               Ada.Text_IO.Close (File => Output);
            end if;
            raise;
      end Assert_Directory;
   begin
      Create_Path (New_Directory => First_Directory);
      Create_Path (New_Directory => Second_Directory);
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);

      Assert_Directory (Expected => Full_Name (First_Directory));

      begin
         Spawn.Pool.Execute
           (Command   => "/bin/true",
            Directory => Missing_Directory);
         Fail (Message => "Missing working directory accepted");

      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      Assert_Directory (Expected => Full_Name (Second_Directory));
      Spawn.Pool.Cleanup;
      Delete_Tree (Directory => Root);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Exists (Name => Root) then
            Delete_Tree (Directory => Root);
         end if;
         raise;
   end Execute_Working_Directories;

   -------------------------------------------------------------------------

   procedure Failed_Init_Cleanup
   is
      use Ada.Directories;

      Directory : constant String := "obj/init-failure-"
        & Anet.Util.Random_String (Len => 8);
   begin
      Create_Directory (New_Directory => Directory);
      begin
         Spawn.Pool.Init
           (Manager_Path   => "/bin/true",
            Socket_Dir     => Directory,
            Socket_Timeout => 0.050,
            Log            => Ada.Text_IO.Put_Line'Access);
         Fail (Message => "short-lived manager unexpectedly initialized");
      exception
         when Anet.Util.Wait_Timeout => null;
      end;
      Delete_Directory (Directory => Directory);
   exception
      when others =>
         if Exists (Name => Directory) then
            Delete_Tree (Directory => Directory);
         end if;
         raise;
   end Failed_Init_Cleanup;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn pool tests");
      T.Add_Test_Routine
        (Routine => Caller_Abort_Releases_Lease'Access,
         Name    => "Release lease after caller task abort");
      T.Add_Test_Routine
        (Routine => Duplicate_Init'Access,
         Name    => "Reject duplicate pool initialization");
      T.Add_Test_Routine
        (Routine => Execute_Bin_True'Access,
         Name    => "Execute /bin/true");
      T.Add_Test_Routine
        (Routine => Execute_Bin_False'Access,
         Name    => "Execute /bin/false");
      T.Add_Test_Routine
        (Routine => Execute_Nonexistent'Access,
         Name    => "Execute nonexistent command");
      T.Add_Test_Routine
        (Routine => Execute_Complex_Command'Access,
         Name    => "Execute complex command");
      T.Add_Test_Routine
        (Routine => Execute_Nonterminating_Command'Access,
         Name    => "Execute non-terminating command");
      T.Add_Test_Routine
        (Routine => Execute_Shell_Environment'Access,
         Name    => "Preserve shell manager environment");
      T.Add_Test_Routine
        (Routine => Execute_Shell_Syntax'Access,
         Name    => "Preserve shell syntax and pipefail");
      T.Add_Test_Routine
        (Routine => Execute_Signal_Mask'Access,
         Name    => "Preserve empty child signal mask");
      T.Add_Test_Routine
        (Routine => Execute_Structured'Access,
         Name    => "Execute structured requests");
      T.Add_Test_Routine
        (Routine => Execute_Merged_Streams'Access,
         Name    => "Share ordered structured output streams");
      T.Add_Test_Routine
        (Routine => Execute_Structured_Environment'Access,
         Name    => "Isolate structured environments");
      T.Add_Test_Routine
        (Routine => Execute_Working_Directories'Access,
         Name    => "Preserve per-request working directories");
      T.Add_Test_Routine
        (Routine => Failed_Init_Cleanup'Access,
         Name    => "Clean failed manager initialization");
      T.Add_Test_Routine
        (Routine => Directory_Collision_Ownership'Access,
         Name    => "Preserve foreign directory on collision");
      T.Add_Test_Routine
        (Routine => Directory_Chmod_Failure_Cleanup'Access,
         Name    => "Clean owned directory after chmod failure");
      T.Add_Test_Routine
        (Routine => Registered_Manager_Log_Failure_Cleanup'Access,
         Name    => "Clean registered manager after ready log failure");
      T.Add_Test_Routine
        (Routine => Parallel_Execution'Access,
         Name    => "Parallel execution");
      T.Add_Test_Routine
        (Routine => Pid_Reset_Precedes_Release'Access,
         Name    => "Reset manager before releasing lease");
      T.Add_Test_Routine
        (Routine => Pid_Setup_Structured_Target'Access,
         Name    => "Preserve structured manager PID callback");
      T.Add_Test_Routine
        (Routine => Pid_Setup_Target'Access,
         Name    => "Preserve manager PID callback");
      T.Add_Test_Routine
        (Routine => Pool_Depleted'Access,
         Name    => "Pool depleted");
      T.Add_Test_Routine
        (Routine => Protocol_Failure_Poisons_Pool'Access,
         Name    => "Poison pool after protocol failure");
      T.Add_Test_Routine
        (Routine => Supervision_Failures_Poison_Pool'Access,
         Name    => "Poison pool after supervision failures");
      T.Add_Test_Routine
        (Routine => Relative_Socket_Transport'Access,
         Name    => "Preserve short relative socket transport");
      T.Add_Test_Routine
        (Routine => Command_Timeout'Access,
         Name    => "Command timeout");
      T.Add_Test_Routine
        (Routine => Timeout_Descendant_Group'Access,
         Name    => "Timeout descendant process group");
      T.Add_Test_Routine
        (Routine => Invalid_Protocol_Buffer_Size'Access,
         Name    => "Enforce minimum protocol buffer size");
      T.Add_Test_Routine
        (Routine => Invalid_Shell_Command'Access,
         Name    => "Preserve invalid shell command failure");
      T.Add_Test_Routine
        (Routine => Invalid_Manager_Path'Access,
         Name    => "Reject relative manager path");
      T.Add_Test_Routine
        (Routine => Invalid_Manager_Path_Nul'Access,
         Name    => "Reject NUL in manager path");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Directory'Access,
         Name    => "Invalid socket directory");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Directory_Nul'Access,
         Name    => "Reject NUL in socket directory");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Path'Access,
         Name    => "Invalid socket path");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Path_Relative'Access,
         Name    => "Invalid relative socket path");
      T.Add_Test_Routine
        (Routine => Cleanup_Relative_Socket'Access,
         Name    => "Cleanup relative socket");
      T.Add_Test_Routine
        (Routine => Cleanup_Removed_Pool_Directory'Access,
         Name    => "Ignore externally removed pool directory");
      T.Add_Test_Routine
        (Routine => Cleanup_Socket_After_Delete_Error'Access,
         Name    => "Continue cleanup after delete error");
      T.Add_Test_Routine
        (Routine => Cleanup_Survives_Log_Error'Access,
         Name    => "Continue cleanup after log error");
      T.Add_Test_Routine
        (Routine => Log_A_File'Access,
         Name    => "Log file contents");
      T.Add_Test_Routine
        (Routine => Connect_Retry_On_Refused'Access,
         Name    => "Retry connect on connection refused");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Invalid_Manager_Path
   is
   begin
      Spawn.Pool.Init (Manager_Path => "spawn_manager");
      Fail (Message => "relative manager path accepted");
   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Manager_Path;

   -------------------------------------------------------------------------

   procedure Invalid_Manager_Path_Nul
   is
   begin
      Spawn.Pool.Init
        (Manager_Path => "/bin/true" & ASCII.NUL & "ignored");
      Fail (Message => "NUL-terminated manager path accepted");
   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Manager_Path_Nul;

   -------------------------------------------------------------------------

   procedure Invalid_Protocol_Buffer_Size
   is
      Minimum_Buffer_Size : constant Positive
        := Spawn.Protocol.Header_Size + 2 * Spawn.Protocol.U32_Size
           + Spawn.Protocol.I64_Size + 2;
   begin
      begin
         Spawn.Pool.Init
           (Manager_Path => Manager_Path,
            Buffer_Size  => Minimum_Buffer_Size - 1);
         Spawn.Pool.Cleanup;
         Fail (Message => "undersized protocol buffer accepted");
      exception
         when Spawn.Pool.Pool_Error => null;
      end;

      Spawn.Pool.Init
        (Manager_Path => Manager_Path,
         Buffer_Size  => Minimum_Buffer_Size);
      Spawn.Pool.Execute (Command => " :", Directory => "");
      Spawn.Pool.Cleanup;
   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Invalid_Protocol_Buffer_Size;

   -------------------------------------------------------------------------

   procedure Invalid_Shell_Command
   is
      Initialized : Boolean := False;
      Setup_Calls : Natural := 0;

      procedure Count_Setup (Pid : GNAT.Expect.Process_Descriptor);
      --  Count attempts to exchange a locally invalid request with a manager.

      procedure Count_Setup (Pid : GNAT.Expect.Process_Descriptor)
      is
         pragma Unreferenced (Pid);
      begin
         Setup_Calls := Setup_Calls + 1;
      end Count_Setup;

      procedure Expect_Command_Failed (Command : String);
      --  Require one locally rejected command to use the compatibility error.

      procedure Expect_Invalid_Timeout;
      --  Require a timeout below -1 to use the compatibility error.

      procedure Expect_Command_Failed (Command : String)
      is
      begin
         Spawn.Pool.Execute
           (Command   => Command,
            Pid_Setup => Count_Setup'Access);
         Fail (Message => "short shell command was accepted");
      exception
         when Error : Spawn.Pool.Command_Failed =>
            Assert
              (Condition => Ada.Exceptions.Exception_Message (Error)
                 = "Command failed: '" & Command & "'",
               Message   => "short shell command diagnostic changed");
         when Spawn.Protocol.Request_Error =>
            Fail (Message => "short shell command exposed Request_Error");
      end Expect_Command_Failed;

      procedure Expect_Invalid_Timeout
      is
      begin
         Spawn.Pool.Execute
           (Command   => " :",
            Timeout   => -2,
            Pid_Setup => Count_Setup'Access);
         Fail (Message => "invalid shell timeout was accepted");
      exception
         when Error : Spawn.Pool.Command_Failed =>
            Assert
              (Condition => Ada.Exceptions.Exception_Message (Error)
                 = "Command failed: ' :'",
               Message   => "invalid timeout diagnostic changed");
         when Constraint_Error =>
            Fail (Message => "invalid timeout exposed Constraint_Error");
      end Expect_Invalid_Timeout;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Expect_Command_Failed (Command => "");
      Expect_Command_Failed (Command => "x");
      Expect_Invalid_Timeout;
      Assert (Condition => Setup_Calls = 0,
              Message   => "invalid shell command acquired a manager");
      Spawn.Pool.Execute (Command => " :");
      Spawn.Pool.Cleanup;
      Initialized := False;
   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         raise;
   end Invalid_Shell_Command;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Directory
   is
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Socket_Dir   => "/nonexistent/nonexistent",
                       Log          => Ada.Text_IO.Put_Line'Access);
      Fail (Message => "Exception expected");

   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Socket_Directory;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Directory_Nul
   is
   begin
      Spawn.Pool.Init
        (Manager_Path => Manager_Path,
         Socket_Dir   => Ada.Directories.Current_Directory
           & ASCII.NUL & "ignored");
      Fail (Message => "NUL-terminated socket directory accepted");
   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Socket_Directory_Nul;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Path
   is
      Dir : constant String := "/tmp/" & Anet.Util.Random_String (Len => 128);
   begin
      Ada.Directories.Create_Directory
        (New_Directory => Dir);

      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Socket_Dir   => Dir,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Fail (Message => "Exception expected");

   exception
      when Spawn.Pool.Pool_Error =>
         Ada.Directories.Delete_Directory (Directory => Dir);
   end Invalid_Socket_Path;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Path_Relative
   is
      use Ada.Directories;

      Dir : constant String := "obj/"
        & Anet.Util.Random_String (Len => 96);
   begin
      Create_Directory (New_Directory => Dir);

      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Socket_Dir   => Dir,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Delete_Directory (Directory => Dir);
      Fail (Message => "Exception expected");

   exception
      when E : Spawn.Pool.Pool_Error =>
         Delete_Directory (Directory => Dir);
         Assert
           (Condition => Ada.Strings.Fixed.Index
              (Source  => Ada.Exceptions.Exception_Message (X => E),
               Pattern => Dir & "/.sp-") > 0,
            Message   => "Relative socket diagnostic omits selected path");
      when others =>
         if Exists (Name => Dir) then
            Delete_Directory (Directory => Dir);
         end if;
         raise;
   end Invalid_Socket_Path_Relative;

   -------------------------------------------------------------------------

   procedure Log_A_File
   is
      Lf : constant String := "data/log_contents";

      Ref_Buffer : constant String :=
        Lf & ": this is a test" & ASCII.LF &
        Lf & ": log file" & ASCII.LF;
   begin
      Pool_Log := Test_Log'Access;
      Log_A_File (Filename => Lf);
      Assert (Condition => Test_Buffer = Ref_Buffer,
              Message   => "Buffer mismatch: '"
              & To_String (Test_Buffer) & "'");

      begin
         Pool_Log := Test_Log_Error'Access;
         Log_A_File (Filename => Lf);
         Fail (Message => "Exception expected");

      exception
         when Test_Log_Exception => null;
      end;

      Pool_Log := null;

   exception
      when others =>
         Pool_Log := null;
         raise;
   end Log_A_File;

   -------------------------------------------------------------------------

   procedure Parallel_Execution
   is
      Task_Array : array (1 .. 4) of Executor;
      Result     : Boolean := True;
   begin
      Spawn.Pool.Init (Manager_Path  => Manager_Path,
                       Manager_Count => 4,
                       Log           => Ada.Text_IO.Put_Line'Access);
      for T in Task_Array'Range loop
         Task_Array (T).Call;
      end loop;

      for T in Task_Array'Range loop
         declare
            Status : Boolean;
         begin
            Task_Array (T).Done (Success => Status);
            Result := Result and Status;
         end;
      end loop;

      Spawn.Pool.Cleanup;

      Assert (Condition => Result,
              Message   => "Parallel execution failed");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         for I in Task_Array'Range loop
            if not Task_Array (I)'Terminated then
               abort Task_Array (I);
            end if;
         end loop;
         raise;
   end Parallel_Execution;

   -------------------------------------------------------------------------

   procedure Pid_Reset_Precedes_Release
   is
      Reset_Count : Natural := 0;

      procedure Check_Lease (Pid : GNAT.Expect.Process_Descriptor);
      --  Verify a nested request cannot acquire the manager being reset.

      procedure Check_Lease (Pid : GNAT.Expect.Process_Descriptor)
      is
         pragma Unreferenced (Pid);
      begin
         Reset_Count := Reset_Count + 1;
         begin
            Spawn.Pool.Execute (Command => "/bin/true");
            Fail (Message => "manager lease was released before reset");
         exception
            when Spawn.Pool.Pool_Error => null;
         end;
      end Check_Lease;

      Request : Spawn.Protocol.Exec_Request_Type;
      Result  : Spawn.Protocol.Result_Type;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path);

      Request.Executable := To_Unbounded_String ("/bin/true");
      Request.Directory := To_Unbounded_String
        (Ada.Directories.Current_Directory);
      Request.Standard_Output := (Mode => Spawn.Protocol.Null_Stream);
      Request.Standard_Error := (Mode => Spawn.Protocol.Null_Stream);
      Request.Timeout := -1;
      Result := Spawn.Pool.Execute
        (Request   => Request,
         Pid_Reset => Check_Lease'Access);
      Assert
        (Condition => Result.Kind = Spawn.Protocol.Exited
           and then Result.Exit_Status = 0,
         Message   => "structured reset request failed");

      Spawn.Pool.Execute
        (Command   => "/bin/true",
         Pid_Reset => Check_Lease'Access);
      Assert
        (Condition => Reset_Count = 2,
         Message   => "manager reset callback count changed");

      --  The manager becomes reusable immediately after reset finishes.
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Pid_Reset_Precedes_Release;

   -------------------------------------------------------------------------

   procedure Pid_Setup_Structured_Target
   is
      use Ada.Directories;

      Manager_PID : C.int := -1;
      Output_Path : constant String := Current_Directory
        & "/obj/pid-setup-parent.out";

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor);
      --  Record the manager selected for the structured request.

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor)
      is
      begin
         Manager_PID := C.int
           (GNAT.Expect.Get_Pid (Descriptor => Descriptor));
      end Capture_Manager;

      Request : Spawn.Protocol.Exec_Request_Type;
      Result  : Spawn.Protocol.Result_Type;
   begin
      if Exists (Name => Output_Path) then
         Delete_File (Name => Output_Path);
      end if;
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Request.Executable := To_Unbounded_String
        (Current_Directory & "/obj/spawn_posix_tests");
      Request.Arguments.Append ("fixture");
      Request.Arguments.Append ("parent");
      Request.Directory := To_Unbounded_String (Current_Directory);
      Request.Standard_Output :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Output_Path));
      Request.Standard_Error := (Mode => Spawn.Protocol.Null_Stream);
      Request.Timeout := 1_000;
      Result := Spawn.Pool.Execute
        (Request   => Request,
         Pid_Setup => Capture_Manager'Access);
      Assert
        (Condition => Result.Kind = Spawn.Protocol.Exited
           and then Result.Exit_Status = 0,
         Message   => "pid-setup fixture failed");
      Assert (Condition => Manager_PID > 0,
              Message   => "pid-setup callback was not called");

      declare
         Output : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => C.int (Integer'Value
              (Ada.Text_IO.Get_Line (File => Output))) = Manager_PID,
            Message   => "pid-setup callback did not receive manager PID");
         Ada.Text_IO.Close (File => Output);
      end;

      Spawn.Pool.Cleanup;
      Delete_File (Name => Output_Path);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Exists (Name => Output_Path) then
            Delete_File (Name => Output_Path);
         end if;
         raise;
   end Pid_Setup_Structured_Target;

   -------------------------------------------------------------------------

   procedure Pid_Setup_Target
   is
      use Ada.Directories;

      Manager_PID : Integer := -1;
      Output_Path : constant String := Current_Directory
        & "/obj/pid-setup-" & Anet.Util.Random_String (Len => 8)
        & ".out";

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor);
      --  Record the process selected by the public compatibility callback.

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor)
      is
      begin
         Manager_PID := Integer
           (GNAT.Expect.Get_Pid (Descriptor => Descriptor));
      end Capture_Manager;
   begin
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command   => "printf '%s\n' ""$PPID"" > " & Output_Path,
         Pid_Setup => Capture_Manager'Access);

      Assert (Condition => Manager_PID > 0,
              Message   => "pid-setup callback was not called");

      declare
         Output : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => Integer'Value
              (Ada.Text_IO.Get_Line (File => Output)) = Manager_PID,
            Message   => "pid-setup callback did not receive manager PID");
         Ada.Text_IO.Close (File => Output);
      end;

      Spawn.Pool.Cleanup;
      Delete_File (Name => Output_Path);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Exists (Name => Output_Path) then
            Delete_File (Name => Output_Path);
         end if;
         raise;
   end Pid_Setup_Target;

   -------------------------------------------------------------------------

   procedure Pool_Depleted
   is
      Task_Array : array (1 .. 8) of Executor;
      Result     : Boolean := True;
   begin
      Spawn.Pool.Init (Manager_Path  => Manager_Path,
                       Manager_Count => 4,
                       Log           => Ada.Text_IO.Put_Line'Access);

      for T in Task_Array'Range loop
         Task_Array (T).Call;
      end loop;

      for T in Task_Array'Range loop
         declare
            Temp : Boolean;
         begin
            Task_Array (T).Done (Success => Temp);

            --  One should fail (pool depleted).

            Result := Result and Temp;
         end;
      end loop;

      Spawn.Pool.Cleanup;
      Assert (Condition => not Result,
              Message   => "No call failed");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         for I in Task_Array'Range loop
            if not Task_Array (I)'Terminated then
               abort Task_Array (I);
            end if;
         end loop;
         raise;
   end Pool_Depleted;

   -------------------------------------------------------------------------

   procedure Protocol_Failure_Poisons_Pool
   is
      Variable_Name : constant String := "SPAWN_TEST_SUPERVISION_STAGE";
      Was_Set       : constant Boolean :=
        Ada.Environment_Variables.Exists (Name => Variable_Name);
      Original      : constant Unbounded_String :=
        (if Was_Set then To_Unbounded_String
           (Ada.Environment_Variables.Value (Name => Variable_Name))
         else Null_Unbounded_String);
      Request     : Protocol.Exec_Request_Type;
      Result      : Protocol.Result_Type;
      Initialized : Boolean := False;

      procedure Restore_Environment;
      --  Restore the external fixture selector after manager startup.

      procedure Restore_Environment
      is
      begin
         if Was_Set then
            Ada.Environment_Variables.Set
              (Name  => Variable_Name,
               Value => To_String (Original));
         else
            Ada.Environment_Variables.Clear (Name => Variable_Name);
         end if;
      end Restore_Environment;
   begin
      Ada.Environment_Variables.Clear (Name => Variable_Name);
      Request.Executable := To_Unbounded_String ("/bin/true");
      Request.Directory := To_Unbounded_String ("/");
      Request.Timeout := -1;

      Spawn.Pool.Init (Manager_Path => Protocol_Failure_Manager_Path);
      Initialized := True;
      Restore_Environment;
      Result := Spawn.Pool.Execute (Request => Request);
      Assert (Condition => Result.Kind = Protocol.Protocol_Failed,
              Message   => "fake manager result was not protocol failure");

      begin
         Result := Spawn.Pool.Execute (Request => Request);
         Fail (Message => "failed pool reused a manager");
      exception
         when E : Spawn.Pool.Pool_Error =>
            Assert
              (Condition => Ada.Exceptions.Exception_Message (X => E)
                 = "spawn manager pool has failed",
               Message   => "failed pool diagnostic differs");
      end;

      Spawn.Pool.Cleanup;
      Initialized := False;

      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;

   exception
      when others =>
         Restore_Environment;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         raise;
   end Protocol_Failure_Poisons_Pool;

   -------------------------------------------------------------------------

   procedure Raise_Delete_Error (Filename : String)
   is
      pragma Unreferenced (Filename);
   begin
      raise Anet.OS.IO_Error with "injected delete failure";
   end Raise_Delete_Error;

   -------------------------------------------------------------------------

   procedure Ready_Log_Error (Msg : String)
   is
   begin
      Test_Buffer := Test_Buffer & Msg & ASCII.LF;
      if (Ada.Strings.Fixed.Index
            (Source  => Msg,
             Pattern => "terminated") > 0
          or else Ada.Strings.Fixed.Index
            (Source  => Msg,
             Pattern => "Timeout occurred") > 0)
        and then not Ada.Text_IO.Is_Open (Ready_Log_File)
      then
         Ada.Text_IO.Create
           (File => Ready_Log_File,
            Name => Ready_Log_Path);
      end if;
      if Ada.Strings.Fixed.Index
        (Source  => Msg,
         Pattern => " ready") > 0
      then
         Ready_Log_Attempts := Ready_Log_Attempts + 1;
         raise Test_Log_Exception;
      end if;
   end Ready_Log_Error;

   -------------------------------------------------------------------------

   procedure Registered_Manager_Log_Failure_Cleanup
   is
      Initialized : Boolean := False;
   begin
      Ready_Log_Attempts := 0;
      Test_Buffer := Null_Unbounded_String;
      if Ada.Directories.Exists (Name => Ready_Log_Path) then
         Ada.Directories.Delete_File (Name => Ready_Log_Path);
      end if;
      begin
         Spawn.Pool.Init
           (Manager_Path => Manager_Path,
            Log          => Ready_Log_Error'Access);
         Initialized := True;
         Fail (Message => "ready-log failure was not propagated");
      exception
         when Test_Log_Exception => null;
      end;
      Assert (Condition => Ready_Log_Attempts = 1,
              Message   => "ready-log failure was not injected exactly once");
      Assert
        (Condition => Ada.Strings.Fixed.Index
           (Source  => To_String (Test_Buffer),
            Pattern => "Unable to") = 0,
         Message   => "registered manager was cleaned through local owner");
      Assert (Condition => Ada.Text_IO.Is_Open (Ready_Log_File),
              Message   => "cleanup did not expose descriptor reuse window");
      Ada.Text_IO.Put_Line (File => Ready_Log_File, Item => "still open");
      Ada.Text_IO.Flush (File => Ready_Log_File);
      Ada.Text_IO.Close (File => Ready_Log_File);
      Ada.Directories.Delete_File (Name => Ready_Log_Path);

      --  Failed Init owns cleanup of the already registered manager. A fresh
      --  pool and request prove that no stale map entry or descriptor remains.
      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Ready_Log_Attempts := 0;
      Test_Buffer := Null_Unbounded_String;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Ready_Log_File) then
            begin
               Ada.Text_IO.Close (File => Ready_Log_File);
            exception
               when others => null;
            end;
         end if;
         if Ada.Directories.Exists (Name => Ready_Log_Path) then
            Ada.Directories.Delete_File (Name => Ready_Log_Path);
         end if;
         if Initialized then
            begin
               Spawn.Pool.Cleanup;
            exception
               when others => null;
            end;
         end if;
         Ready_Log_Attempts := 0;
         Test_Buffer := Null_Unbounded_String;
         raise;
   end Registered_Manager_Log_Failure_Cleanup;

   -------------------------------------------------------------------------

   procedure Relative_Socket_Transport
   is
      use Ada.Directories;

      Directory : constant String := "obj/deep-"
        & Anet.Util.Random_String (Len => 68);
      Address_Suffix : constant String
        := "/.sp-123456789012/m-12345678";
      Relative_Address : constant String := Directory & Address_Suffix;
      Initialized : Boolean := False;
   begin
      Create_Directory (New_Directory => Directory);
      Assert
        (Condition => Anet.Sockets.Unix.Is_Valid
           (Path => Relative_Address),
         Message => "relative socket fixture exceeds the transport limit");
      Assert
        (Condition => not Anet.Sockets.Unix.Is_Valid
           (Path => Full_Name (Name => Directory) & Address_Suffix),
         Message => "absolute socket fixture does not exceed the limit");

      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Socket_Dir   => Directory,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Delete_Directory (Directory => Directory);

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         if Exists (Name => Directory) then
            Delete_Tree (Directory => Directory);
         end if;
         raise;
   end Relative_Socket_Transport;

   -------------------------------------------------------------------------

   procedure Supervision_Failures_Poison_Pool
   is
      Poison_Stages : constant array (Positive range <>) of
        Protocol.Failure_Stage :=
          (Protocol.No_Failure,
           Protocol.Enable_Subreaper,
           Protocol.Create_Error_Pipe,
           Protocol.Process_Group,
           Protocol.Reset_Signals,
           Protocol.Wait_Child,
           Protocol.Terminate_Group);
      Variable_Name : constant String :=
        "SPAWN_TEST_SUPERVISION_STAGE";
      Was_Set       : constant Boolean :=
        Ada.Environment_Variables.Exists (Name => Variable_Name);
      Original      : constant Unbounded_String :=
        (if Was_Set then To_Unbounded_String
           (Ada.Environment_Variables.Value (Name => Variable_Name))
         else Null_Unbounded_String);
      Request       : Protocol.Exec_Request_Type;
      Result        : Protocol.Result_Type;
      Initialized   : Boolean := False;

      procedure Restore_Environment;
      --  Restore the environment after the fake manager has inherited it.

      procedure Restore_Environment
      is
      begin
         if Was_Set then
            Ada.Environment_Variables.Set
              (Name  => Variable_Name,
               Value => To_String (Original));
         else
            Ada.Environment_Variables.Clear (Name => Variable_Name);
         end if;
      end Restore_Environment;
   begin
      Request.Executable := To_Unbounded_String ("/bin/true");
      Request.Directory := To_Unbounded_String ("/");
      Request.Timeout := -1;
      for Stage of Poison_Stages loop
         Ada.Environment_Variables.Set
           (Name  => Variable_Name,
            Value => Ada.Strings.Fixed.Trim
              (Source => Natural'Image
                 (Protocol.Failure_Stage'Pos (Stage)),
               Side   => Ada.Strings.Both));
         Spawn.Pool.Init (Manager_Path => Protocol_Failure_Manager_Path);
         Initialized := True;
         Restore_Environment;

         Result := Spawn.Pool.Execute (Request => Request);
         Assert
           (Condition => Result.Kind = Protocol.Spawn_Failed
              and then Result.Failure.Stage = Stage,
            Message   => "fake manager result did not retain " & Stage'Image);

         begin
            Result := Spawn.Pool.Execute (Request => Request);
            Fail (Message => "failed pool reused a manager after "
                  & Stage'Image);
         exception
            when E : Spawn.Pool.Pool_Error =>
               Assert
                 (Condition => Ada.Exceptions.Exception_Message (X => E)
                    = "spawn manager pool has failed",
                  Message   => "pool diagnostic differs after "
                    & Stage'Image);
         end;

         Spawn.Pool.Cleanup;
         Initialized := False;
      end loop;

      Spawn.Pool.Init (Manager_Path => Manager_Path);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;

   exception
      when others =>
         Restore_Environment;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         raise;
   end Supervision_Failures_Poison_Pool;

   -------------------------------------------------------------------------

   procedure Test_Log (Msg : String)
   is
   begin
      Test_Buffer := Test_Buffer & Msg & ASCII.LF;
   end Test_Log;

   -------------------------------------------------------------------------

   procedure Test_Log_Error (Msg : String)
   is
   begin
      raise Test_Log_Exception;
   end Test_Log_Error;

   -------------------------------------------------------------------------

   procedure Timeout_Descendant_Group
   is
      use Ada.Directories;

      Pid_File    : constant String := "obj/timeout-descendant.pid";
      Initialized : Boolean := False;
   begin
      if Exists (Name => Pid_File) then
         Delete_File (Name => Pid_File);
      end if;
      Spawn.Pool.Init (Manager_Path => Manager_Path,
                       Log          => Ada.Text_IO.Put_Line'Access);
      Initialized := True;

      begin
         Spawn.Pool.Execute
           (Command => "sleep 60 & echo $! > " & Pid_File & "; wait",
            Timeout => 500);
         Fail (Message => "Failure expected");
      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      Spawn.Pool.Execute
        (Command => "test -s " & Pid_File
         & " && ! kill -0 $(cat " & Pid_File & ") 2>/dev/null");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Delete_File (Name => Pid_File);

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         if Exists (Name => Pid_File) then
            Delete_File (Name => Pid_File);
         end if;
         raise;
   end Timeout_Descendant_Group;

end Spawn.Pool.Tests;
