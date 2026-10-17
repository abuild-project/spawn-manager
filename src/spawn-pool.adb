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
with Ada.Strings.Fixed;
with Ada.Containers.Ordered_Maps;
with Ada.Exceptions;
with Ada.Finalization;
with Interfaces;
with Interfaces.C;
with Interfaces.C.Strings;

with GNAT.OS_Lib;

with Anet.OS;
with Anet.Util;

with Spawn.Transport;

package body Spawn.Pool is

   package C renames Interfaces.C;
   package CS renames Interfaces.C.Strings;

   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type C.int;
   use type CS.chars_ptr;
   use type GNAT.OS_Lib.Argument_List_Access;
   use type GNAT.Expect.Expect_Match;
   use type Spawn.Protocol.Result_Kind;

   Addr_Base : constant String := "m-";
   Pool_Base : constant String := ".sp-";

   function C_Chmod (Path : CS.chars_ptr; Mode : C.unsigned) return C.int
     with Import,
          Convention    => C,
          External_Name => "chmod";
   --  Set exact owner-only permissions after mkdir regardless of caller umask.

   function C_Mkdir (Path : CS.chars_ptr; Mode : C.unsigned) return C.int
     with Import,
          Convention    => C,
          External_Name => "mkdir";
   --  Atomically create the private directory and detect name collisions.

   package Socket_Maps is new Ada.Containers.Ordered_Maps
     (Key_Type     => Unbounded_String,
      Element_Type => Socket_Container);

   package Lease_Guards is
      type Guard is new Ada.Finalization.Limited_Controlled with record
         Container : Socket_Container;
         Active    : Boolean := False;
      end record;
      --  Task-owned manager lease whose finalizer also runs during task abort.

      procedure Abandon (Lease : in out Guard);
      --  Poison the complete pool and return its active-count slot once.

      overriding
      procedure Finalize (Lease : in out Guard);
      --  Abandon a lease when task abort skips ordinary exception handlers.

      procedure Release (Lease : in out Guard);
      --  Return a successfully used manager to the available pool.
   end Lease_Guards;

   subtype Lease_Guard is Lease_Guards.Guard;

   procedure Create_Private_Directory
     (Path    : String;
      Created : not null access Boolean);
   --  Atomically create Path with no group or other access. Set Created as
   --  soon as mkdir transfers ownership, including across a chmod exception.

   procedure Require_C_String (Value : String; Name : String);
   --  Reject a pool input which a downstream C API would silently truncate.

   function Poisons_Pool (Result : Protocol.Result_Type) return Boolean;
   --  Return whether Result leaves manager supervision unsafe for reuse.

   procedure Remove_Pool_Directory (Path : String);
   --  Remove an empty private socket directory without aborting cleanup. An
   --  already absent directory is clean because its parent may be
   --  caller-owned.

   function Result_Timeout
     (Child_Timeout : Protocol.Timeout_Milliseconds)
      return Protocol.Timeout_Milliseconds;
   --  Bound the first result byte after a finite child deadline.

   protected Sockets
   is
      procedure Abandon_Socket (Lease : in out Lease_Guard);
      --  Return one failed lease without making its manager reusable.

      procedure Begin_Cleanup
        (Snapshot       : out Socket_Maps.Map;
         Pool_Directory : out Unbounded_String);
      --  Stop new leases and snapshot managers for out-of-lock cancellation.

      procedure Cancel_Initialization;
      --  Forget an uncreated pool directory after initialization fails before
      --  any manager or filesystem ownership exists.

      procedure Finish_Cleanup;
      --  Clear manager state after all out-of-lock cleanup has completed.

      procedure Insert_Socket (S : Socket_Container);
      --  Insert new socket into store.

      procedure Get_Socket (Lease : in out Lease_Guard);
      --  Select a non-busy manager and activate Lease atomically. Task abort
      --  is deferred for the complete protected action, so there is no gap
      --  between incrementing Active_Count and arming Lease's finalizer.

      procedure Release_Socket (Lease : in out Lease_Guard);
      --  Release given socket container.

      procedure Start_Initialization (Pool_Directory : String);
      --  Record one new empty pool's private socket directory.

      entry Wait_For_No_Active;
      --  Wait until every caller has returned or abandoned its lease.
   private
      Active_Count  : Natural := 0;
      Data          : Socket_Maps.Map;
      Directory     : Unbounded_String;
      Failed        : Boolean := False;
      Shutting_Down : Boolean := False;
   end Sockets;

   function Exchange_Request
     (Lease                 : in out Lease_Guard;
      Request               : Ada.Streams.Stream_Element_Array;
      First_Byte_Timeout_MS : Protocol.Timeout_Milliseconds;
      Pid_Setup             : access procedure
        (Pid : GNAT.Expect.Process_Descriptor))
      return Protocol.Result_Type;
   --  Acquire one manager, run setup and exchange one exact frame.

   function Send_Receive
     (Lease                 : in out Lease_Guard;
      Request               : Ada.Streams.Stream_Element_Array;
      First_Byte_Timeout_MS : Protocol.Timeout_Milliseconds)
      return Protocol.Result_Type;
   --  Exchange one exact frame, poisoning Lease on transport failure.

   procedure Reset_And_Release
     (Lease     : in out Lease_Guard;
      Pid_Reset : access procedure
        (Pid : GNAT.Expect.Process_Descriptor));
   --  Reset the manager while Lease is exclusive, then make it reusable.

   -------------------------------------------------------------------------

   package body Lease_Guards is

      procedure Abandon (Lease : in out Guard)
      is
      begin
         Sockets.Abandon_Socket (Lease => Lease);
      end Abandon;

      overriding
      procedure Finalize (Lease : in out Guard)
      is
      begin
         Abandon (Lease);
      exception
         when others => null;
      end Finalize;

      procedure Release (Lease : in out Guard)
      is
      begin
         Sockets.Release_Socket (Lease => Lease);
      end Release;

   end Lease_Guards;

   -------------------------------------------------------------------------

   procedure Cleanup
   is
      Snapshot       : Socket_Maps.Map;
      Position       : Socket_Maps.Cursor;
      Pool_Directory : Unbounded_String;

      procedure Cleanup_Log (Msg : String);
      --  Report a best-effort diagnostic without changing cleanup ownership.

      procedure Dispose_Manager (Manager : in out Socket_Container);
      --  Reap and release one manager after no caller can own its lease.

      procedure Interrupt_Manager (Manager : in out Socket_Container);
      --  Ask one manager to stop while retaining cleanup progress on error.

      procedure Cleanup_Log (Msg : String)
      is
      begin
         if Pool_Log /= null then
            Pool_Log (Msg => Msg);
         end if;
      exception
         when others =>
            --  Cleanup owns the complete snapshot; a diagnostic callback
            --  must not prevent the remaining manager releases.
            null;
      end Cleanup_Log;

      procedure Dispose_Manager (Manager : in out Socket_Container)
      is
         Match : GNAT.Expect.Expect_Match := 0;
      begin
         begin
            GNAT.Expect.Expect
              (Descriptor => Manager.Pid,
               Result     => Match,
               Regexp     => "",
               Timeout    => 3000);
         exception
            when GNAT.Expect.Process_Died =>
               Cleanup_Log
                 (Msg => "Manager " & To_String (Manager.Socket_Address)
                    & " terminated");
            when E : others =>
               Cleanup_Log
                 (Msg => "Unable to wait for manager "
                    & To_String (Manager.Socket_Address) & ": "
                    & Ada.Exceptions.Exception_Message (X => E));
         end;

         if Match = GNAT.Expect.Expect_Timeout then
            Cleanup_Log
              (Msg => "Timeout occurred, KILL manager "
                 & To_String (Manager.Socket_Address));
         end if;

         begin
            GNAT.Expect.Close (Descriptor => Manager.Pid);
         exception
            when E : others =>
               Cleanup_Log
                 (Msg => "Unable to close manager "
                    & To_String (Manager.Socket_Address) & ": "
                    & Ada.Exceptions.Exception_Message (X => E));
         end;
         begin
            Manager.Socket.Close;
         exception
            when E : others =>
               Cleanup_Log
                 (Msg => "Unable to close manager socket "
                    & To_String (Manager.Socket_Address) & ": "
                    & Ada.Exceptions.Exception_Message (X => E));
         end;
         begin
            Remove_Socket_File
              (Filename => To_String (Manager.Cleanup_Path));
         exception
            when E : others =>
               Cleanup_Log
                 (Msg => "Unable to remove manager socket "
                    & To_String (Manager.Socket_Address) & ": "
                    & Ada.Exceptions.Exception_Message (X => E));
         end;
         begin
            Anet.OS.Delete_File
              (Filename => To_String (Manager.Cleanup_Path) & ".log");
         exception
            when E : others =>
               Cleanup_Log
                 (Msg => "Unable to remove manager log "
                    & To_String (Manager.Socket_Address) & ": "
                    & Ada.Exceptions.Exception_Message (X => E));
         end;
         Free (X => Manager.Socket);
      end Dispose_Manager;

      procedure Interrupt_Manager (Manager : in out Socket_Container)
      is
      begin
         GNAT.Expect.Interrupt (Descriptor => Manager.Pid);
      exception
         when E : others =>
            Cleanup_Log
              (Msg => "Unable to interrupt manager "
                 & To_String (Manager.Socket_Address) & ": "
                 & Ada.Exceptions.Exception_Message (X => E));
      end Interrupt_Manager;
   begin
      Sockets.Begin_Cleanup
        (Snapshot       => Snapshot,
         Pool_Directory => Pool_Directory);

      --  Cancellation must happen before waiting for active leases: the
      --  manager contains its active request and exits, so transport closure
      --  wakes callers which must return or abandon their leases.

      Position := Snapshot.First;
      while Socket_Maps.Has_Element (Position => Position) loop
         declare
            Manager : Socket_Container
              := Socket_Maps.Element (Position => Position);
         begin
            Interrupt_Manager (Manager => Manager);
         end;
         Socket_Maps.Next (Position => Position);
      end loop;

      Sockets.Wait_For_No_Active;

      --  No caller owns a snapshot entry now. Clear protected state before
      --  fallible descriptor and filesystem cleanup so no diagnostic or OS
      --  error can leave the lifecycle permanently marked as shutting down.
      Sockets.Finish_Cleanup;

      Position := Snapshot.First;
      while Socket_Maps.Has_Element (Position => Position) loop
         declare
            Manager : Socket_Container
              := Socket_Maps.Element (Position => Position);
         begin
            Dispose_Manager (Manager => Manager);
         end;
         Socket_Maps.Next (Position => Position);
      end loop;

      begin
         Remove_Pool_Directory (Path => To_String (Pool_Directory));
      exception
         when E : others =>
            Cleanup_Log
              (Msg => "Unable to remove private socket directory: "
                 & Ada.Exceptions.Exception_Message (X => E));
      end;
   end Cleanup;

   -------------------------------------------------------------------------

   procedure Connect_Retry_On_Refused
     (Socket : Socket_Handle;
      Path   : Anet.Sockets.Unix.Path_Type;
      Count  : Positive)
   is

      function Is_Refused (Msg : String) return Boolean;
      --  Returns True if the given message contains the pattern 'Connection
      --  refused'.

      function Is_Refused (Msg : String) return Boolean
      is
      begin
         return Ada.Strings.Fixed.Index
           (Source  => Msg,
            Pattern => "Connection refused") > 0;
      end Is_Refused;

      Refused : Boolean;
   begin
      for I in 1 .. Count loop
         Refused := False;

         begin
            Socket.Connect (Path => Path);

         exception
            when E : Anet.Socket_Error =>
               Refused := Is_Refused
                 (Msg => Ada.Exceptions.Exception_Message (X => E));
               if not Refused then
                  raise;
               end if;
         end;

         if not Refused then
            return;
         end if;

         Pool_Log (Msg => "Socket '" & String (Path) & "' refused "
            & "connection, retrying in one second ...");
         delay 1.0;
      end loop;

      raise Connection_Refused with "Socket '" & String (Path) & "' still "
        & "refuses connection after" & Count'Img & " tries";
   end Connect_Retry_On_Refused;

   -------------------------------------------------------------------------

   procedure Create_Private_Directory
     (Path    : String;
      Created : not null access Boolean)
   is
      C_Path : CS.chars_ptr := CS.New_String (Path);
      Error_Number : Integer := 0;
      Result       : C.int;
   begin
      Created.all := False;
      Result := C_Mkdir (Path => C_Path, Mode => 8#700#);
      if Result = 0 then
         Created.all := True;
         Result := C_Chmod (Path => C_Path, Mode => 8#700#);
      end if;
      if Result /= 0 then
         Error_Number := GNAT.OS_Lib.Errno;
      end if;
      CS.Free (C_Path);
      if Result /= 0 then
         raise Pool_Error with "unable to create private socket directory '"
           & Path & "': " & GNAT.OS_Lib.Errno_Message
             (Err => Error_Number);
      end if;
   exception
      when others =>
         if C_Path /= CS.Null_Ptr then
            CS.Free (C_Path);
         end if;
         raise;
   end Create_Private_Directory;

   -------------------------------------------------------------------------

   procedure Delete_Socket_File (Filename : String)
   is
   begin
      Anet.OS.Delete_File (Filename => Filename);
   end Delete_Socket_File;

   -------------------------------------------------------------------------

   function Exchange_Request
     (Lease                 : in out Lease_Guard;
      Request               : Ada.Streams.Stream_Element_Array;
      First_Byte_Timeout_MS : Protocol.Timeout_Milliseconds;
      Pid_Setup             : access procedure
        (Pid : GNAT.Expect.Process_Descriptor))
      return Protocol.Result_Type
   is
   begin
      Sockets.Get_Socket (Lease);
      Pool_Log (Msg => "Found available socket "
         & To_String (Lease.Container.Socket_Address));
      Pid_Setup (Lease.Container.Pid);
      return Send_Receive
        (Lease                 => Lease,
         Request               => Request,
         First_Byte_Timeout_MS => First_Byte_Timeout_MS);
   end Exchange_Request;

   -------------------------------------------------------------------------

   function Execute
     (Request   : Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access;
      Pid_Reset : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
      return Protocol.Result_Type
   is
   begin
      declare
         Length : constant Positive := Protocol.Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size));
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Lease : Lease_Guard;
         Result : Protocol.Result_Type;
      begin
         Protocol.Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size),
            Data         => Data);
         begin
            Result := Exchange_Request
              (Lease                 => Lease,
               Request               => Data,
               First_Byte_Timeout_MS =>
                 Result_Timeout (Child_Timeout => Request.Timeout),
               Pid_Setup             => Pid_Setup);
         exception
            when Spawn.Protocol.Protocol_Error
               | Spawn.Transport.Extra_Data
               | Spawn.Transport.Peer_Closed
               | Spawn.Transport.Transport_Error
               | Spawn.Transport.Transport_Timeout =>
               return
                 (Kind       => Protocol.Protocol_Failed,
                  Diagnostic => To_Unbounded_String
                    ("manager transport failed"));
         end;
         if Poisons_Pool (Result => Result) then
            return Result;
         end if;
         Reset_And_Release (Lease => Lease, Pid_Reset => Pid_Reset);
         return Result;
      end;
   exception
      when Spawn.Protocol.Protocol_Error
         | Spawn.Protocol.Request_Error =>
         return
           (Kind       => Protocol.Request_Rejected,
            Diagnostic => To_Unbounded_String ("invalid execution request"));
   end Execute;

   -------------------------------------------------------------------------

   procedure Execute
     (Command   : String;
      Directory : String  := Ada.Directories.Current_Directory;
      Timeout   : Integer := -1;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access;
      Pid_Reset : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
   is
      Request : Protocol.Shell_Request_Type
        := (Command   => Null_Unbounded_String,
            Directory => Null_Unbounded_String,
            Timeout   => -1);
      procedure Execute_Request;
      --  Encode, exchange and classify one validated compatible request.

      procedure Execute_Request
      is
         Length : constant Positive := Protocol.Shell_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size));
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Lease  : Lease_Guard;
         Result : Protocol.Result_Type;
      begin
         Protocol.Encode_Shell_Request
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size),
            Data         => Data);

         begin
            Result := Exchange_Request
              (Lease                 => Lease,
               Request               => Data,
               First_Byte_Timeout_MS =>
                 Result_Timeout (Child_Timeout => Request.Timeout),
               Pid_Setup             => Pid_Setup);
         exception
            when Spawn.Protocol.Protocol_Error
               | Spawn.Transport.Extra_Data
               | Spawn.Transport.Peer_Closed
               | Spawn.Transport.Transport_Error
               | Spawn.Transport.Transport_Timeout =>
               raise Command_Failed with
                 "Manager transport failed for command: '" & Command & "'";
         end;

         if Poisons_Pool (Result => Result) then
            raise Command_Failed with
              (if Result.Kind = Protocol.Protocol_Failed
               then "Manager protocol failed for command: '"
               else "Manager supervision failed for command: '")
              & Command & "'";
         end if;

         Reset_And_Release (Lease => Lease, Pid_Reset => Pid_Reset);

         if Result.Kind /= Protocol.Exited
           or else Result.Exit_Status /= 0
         then
            raise Command_Failed with "Command failed: '" & Command & "'";
         end if;
      end Execute_Request;
   begin
      if Timeout < -1 then
         raise Command_Failed with "Command failed: '" & Command & "'";
      end if;
      Request :=
        (Command   => To_Unbounded_String (Command),
         Directory => To_Unbounded_String (Directory),
         Timeout   => Protocol.Timeout_Milliseconds (Timeout));
      Pool_Log (Msg => "Executing command '" & Command & "'");
      Execute_Request;
   exception
      when Spawn.Protocol.Protocol_Error
         | Spawn.Protocol.Request_Error =>
         raise Command_Failed with "Command failed: '" & Command & "'";
   end Execute;

   -------------------------------------------------------------------------

   procedure Execute_Checked
     (Request   : Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access;
      Pid_Reset : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
   is
      Result : constant Protocol.Result_Type := Execute
        (Request   => Request,
         Pid_Setup => Pid_Setup,
         Pid_Reset => Pid_Reset);
   begin
      if Result.Kind /= Protocol.Exited or else Result.Exit_Status /= 0 then
         raise Command_Failed with "Structured command failed ["
           & Result.Kind'Image & "]";
      end if;
   end Execute_Checked;

   -------------------------------------------------------------------------

   procedure Init
     (Manager_Path   : String;
      Manager_Count  : Positive      := 1;
      Socket_Dir     : String        := "/tmp";
      Socket_Timeout : Duration      := 3.0;
      Buffer_Size    : Positive      := 8192;
      Log            : Log_Procedure := No_Log'Access)
   is
      procedure Connect_And_Register
        (Pid             : GNAT.Expect.Process_Descriptor;
         Address         : String;
         Cleanup_Address : String);
      --  Connect one started manager and transfer its socket into the pool.

      procedure Start_Manager
        (Pool_Address      : String;
         Cleanup_Directory : String);
      --  Spawn, connect and register one manager, or undo partial startup.

      procedure Connect_And_Register
        (Pid             : GNAT.Expect.Process_Descriptor;
         Address         : String;
         Cleanup_Address : String)
      is
         Socket   : Socket_Handle := new Anet.Sockets.Unix.TCP_Socket_Type;
         Inserted : Boolean := False;
      begin
         Socket.Init;
         Spawn.Transport.Set_Close_On_Exec
           (Descriptor => Socket.Get_Socket);
         Connect_Retry_On_Refused
           (Socket => Socket,
            Path   => Anet.Sockets.Unix.Path_Type (Address),
            Count  => 5);
         Socket.Set_Nonblocking_Mode;
         Sockets.Insert_Socket
           (S =>
              (Socket_Address => To_Unbounded_String (Address),
               Cleanup_Path   => To_Unbounded_String (Cleanup_Address),
               Pid            => Pid,
               Socket         => Socket,
               Available      => True));
         Inserted := True;
      exception
         when others =>
            if not Inserted then
               begin
                  Socket.Close;
               exception
                  when others => null;
               end;
               Free (X => Socket);
               Log_A_File (Filename => Cleanup_Address & ".log");
            end if;
            raise;
      end Connect_And_Register;

      procedure Start_Manager
        (Pool_Address      : String;
         Cleanup_Directory : String)
      is
         Address_Suffix : constant String := Addr_Base
           & Anet.Util.Random_String (Len => 8);
         Address : constant String := Ada.Directories.Compose
           (Containing_Directory => Pool_Address,
            Name                 => Address_Suffix);
         Cleanup_Address : constant String := Ada.Directories.Compose
           (Containing_Directory => Cleanup_Directory,
            Name                 => Address_Suffix);

         Arguments  : GNAT.OS_Lib.Argument_List_Access := null;
         Pid        : GNAT.Expect.Process_Descriptor;
         Registered : Boolean := False;
         Started    : Boolean := False;

         procedure Stop_Unregistered_Manager;
         --  Reap the manager and remove files left by failed registration.

         procedure Stop_Unregistered_Manager
         is
            Match : GNAT.Expect.Expect_Match := 0;
         begin
            if not Started or else Registered then
               return;
            end if;
            begin
               GNAT.Expect.Interrupt (Descriptor => Pid);
            exception
               when others => null;
            end;
            begin
               GNAT.Expect.Expect
                 (Descriptor => Pid,
                  Result     => Match,
                  Regexp     => "",
                  Timeout    => 1000);
            exception
               when GNAT.Expect.Process_Died => null;
               when others                  => null;
            end;
            begin
               GNAT.Expect.Close (Descriptor => Pid);
            exception
               when others => null;
            end;
            begin
               Anet.OS.Delete_File (Filename => Cleanup_Address);
            exception
               when others => null;
            end;
            begin
               Anet.OS.Delete_File (Filename => Cleanup_Address & ".log");
            exception
               when others => null;
            end;
         end Stop_Unregistered_Manager;
      begin
         if not Anet.Sockets.Unix.Is_Valid (Path => Address) then
            raise Pool_Error with "UNIX path too long '" & Address & "'";
         end if;

         Arguments := new GNAT.OS_Lib.Argument_List'
           (new String'(Buffer_Size'Img),
            new String'(Address));
         begin
            GNAT.Expect.Non_Blocking_Spawn
              (Descriptor  => Pid,
               Command     => Manager_Path,
               Args        => Arguments.all,
               Buffer_Size => 0);
            Started := True;
            Pool_Log (Msg => "Forked manager " & Address);
         exception
            when GNAT.Expect.Invalid_Process =>
               GNAT.OS_Lib.Free (Arguments);
               raise Command_Failed with
                 "Unable to fork manager " & Manager_Path;
         end;
         GNAT.OS_Lib.Free (Arguments);

         Pool_Log
           (Msg => "Waiting for socket '" & Address
              & "' to become available");
         Anet.Util.Wait_For_File
           (Path     => Address,
            Timespan => Socket_Timeout);
         Connect_And_Register
           (Pid             => Pid,
            Address         => Address,
            Cleanup_Address => Cleanup_Address);
         --  From this point the protected pool owns the manager. Set the
         --  surrounding flag before invoking the fallible user callback so
         --  unwind cleanup cannot treat the registered manager as local.
         Registered := True;
         Pool_Log (Msg => "Socket " & Address & " ready");
      exception
         when others =>
            if Arguments /= null then
               GNAT.OS_Lib.Free (Arguments);
            end if;
            Stop_Unregistered_Manager;
            raise;
      end Start_Manager;
   begin
      Require_C_String (Value => Manager_Path, Name => "manager path");
      Require_C_String (Value => Socket_Dir, Name => "socket directory");
      if Manager_Path'Length = 0
        or else Manager_Path (Manager_Path'First) /= '/'
      then
         raise Pool_Error with "manager path must be absolute";
      end if;
      if Buffer_Size < Protocol.Minimum_Shell_Request_Frame_Size
        or else Buffer_Size > Protocol.Maximum_Frame_Size
      then
         raise Pool_Error with "invalid protocol buffer size";
      end if;

      --  Check if socket directory exists

      if not Ada.Directories.Exists (Name => Socket_Dir) then
         raise Pool_Error with "Socket directory '" & Socket_Dir
           & "' does not exist";
      end if;

      declare
         Pool_Name : constant String := Pool_Base
           & Anet.Util.Random_String (Len => 12);
         Pool_Address : constant String := Ada.Directories.Compose
           (Containing_Directory => Socket_Dir,
            Name                 => Pool_Name);
         Cleanup_Directory : constant String := Ada.Directories.Compose
           (Containing_Directory => Ada.Directories.Full_Name
              (Name => Socket_Dir),
            Name                 => Pool_Name);
         Directory_Owned : aliased Boolean := False;
      begin
         Sockets.Start_Initialization
           (Pool_Directory => Cleanup_Directory);
         Pool_Log := Log;
         Cmd_Buffer_Size := Ada.Streams.Stream_Element_Offset (Buffer_Size);
         begin
            Create_Private_Directory
              (Path    => Pool_Address,
               Created => Directory_Owned'Access);
            for M in 1 .. Manager_Count loop
               pragma Unreferenced (M);
               Start_Manager
                 (Pool_Address      => Pool_Address,
                  Cleanup_Directory => Cleanup_Directory);
            end loop;
         exception
            when others =>
               if Directory_Owned then
                  Cleanup;
               else
                  Sockets.Cancel_Initialization;
               end if;
               raise;
         end;
      end;
   end Init;

   -------------------------------------------------------------------------

   procedure Log_A_File (Filename : String)
   is
      Log_File : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Name => Filename) then
         Pool_Log (Msg => "Unable to log contents of nonexistent file '"
            & Filename & "' - non-debug build?");
         return;
      end if;

      Ada.Text_IO.Open
        (File => Log_File,
         Mode => Ada.Text_IO.In_File,
         Name => Filename,
         Form => "shared=no");

      while not Ada.Text_IO.End_Of_File (File => Log_File) loop
         Pool_Log
           (Msg => Filename & ": "
              & Ada.Text_IO.Get_Line (File => Log_File));
      end loop;

      Ada.Text_IO.Close (File => Log_File);

   exception
      when E : others =>
         if Ada.Text_IO.Is_Open (File => Log_File) then
            Ada.Text_IO.Close (File => Log_File);
         end if;
         Pool_Log (Msg => "Error logging file contents '"
            & Filename & "': " & Ada.Exceptions.Exception_Message (X => E));
   end Log_A_File;

   -------------------------------------------------------------------------

   function Poisons_Pool (Result : Protocol.Result_Type) return Boolean
   is
   begin
      case Result.Kind is
         when Protocol.Protocol_Failed =>
            return True;
         when Protocol.Spawn_Failed =>
            --  The protocol keeps the detailed stage but merges internal and
            --  child-spawn result classes. These stages can originate in
            --  manager-side supervision; fail closed because the preceding
            --  request may not be contained or reaped.
            case Result.Failure.Stage is
               when Protocol.No_Failure
                  | Protocol.Enable_Subreaper
                  | Protocol.Create_Error_Pipe
                  | Protocol.Process_Group
                  | Protocol.Reset_Signals
                  | Protocol.Wait_Child
                  | Protocol.Terminate_Group =>
                  return True;
               when others =>
                  return False;
            end case;
         when others =>
            return False;
      end case;
   end Poisons_Pool;

   -------------------------------------------------------------------------

   procedure Remove_Pool_Directory (Path : String)
   is
   begin
      if Path'Length > 0
        and then Ada.Directories.Exists (Name => Path)
      then
         Ada.Directories.Delete_Directory (Directory => Path);
      end if;
   exception
      when E : others =>
         Pool_Log (Msg => "Unable to remove private socket directory '" & Path
            & "': " & Ada.Exceptions.Exception_Message (X => E));
   end Remove_Pool_Directory;

   -------------------------------------------------------------------------

   procedure Remove_Socket_File (Filename : String)
   is
   begin
      Socket_File_Delete (Filename => Filename);

   exception
      when E : Anet.OS.IO_Error =>
         Pool_Log (Msg => "Unable to remove manager socket '"
            & Filename & "': "
            & Ada.Exceptions.Exception_Message (X => E));
   end Remove_Socket_File;

   -------------------------------------------------------------------------

   procedure Require_C_String (Value : String; Name : String)
   is
   begin
      if Ada.Strings.Fixed.Index
        (Source  => Value,
         Pattern => (1 => ASCII.NUL)) /= 0
      then
         raise Pool_Error with Name & " contains NUL";
      end if;
   end Require_C_String;

   -------------------------------------------------------------------------

   procedure Reset_And_Release
     (Lease     : in out Lease_Guard;
      Pid_Reset : access procedure
        (Pid : GNAT.Expect.Process_Descriptor))
   is
   begin
      Pid_Reset (Lease.Container.Pid);
      Lease_Guards.Release (Lease);
      Pool_Log (Msg => "Socket "
         & To_String (Lease.Container.Socket_Address)
         & " released");
   end Reset_And_Release;

   -------------------------------------------------------------------------

   function Result_Timeout
     (Child_Timeout : Protocol.Timeout_Milliseconds)
      return Protocol.Timeout_Milliseconds
   is
   begin
      if Child_Timeout = -1 then
         return -1;
      elsif Child_Timeout
        > Protocol.Timeout_Milliseconds'Last
          - Interfaces.Integer_64
            (Spawn.Transport.Frame_Completion_Timeout_MS)
      then
         return Protocol.Timeout_Milliseconds'Last;
      else
         return Child_Timeout + Interfaces.Integer_64
           (Spawn.Transport.Frame_Completion_Timeout_MS);
      end if;
   end Result_Timeout;

   -------------------------------------------------------------------------

   function Send_Receive
     (Lease                 : in out Lease_Guard;
      Request               : Ada.Streams.Stream_Element_Array;
      First_Byte_Timeout_MS : Protocol.Timeout_Milliseconds)
      return Protocol.Result_Type
   is
      Result : Protocol.Result_Type;
   begin
      Pool_Log (Msg => "Sending request using socket "
         & To_String (Lease.Container.Socket_Address));

      Spawn.Transport.Send_Frame
        (Descriptor => Lease.Container.Socket.Get_Socket,
         Data       => Request);
      declare
         Response : constant Ada.Streams.Stream_Element_Array
           := Spawn.Transport.Receive_Frame
             (Descriptor            => Lease.Container.Socket.Get_Socket,
              Active_Bound          => Positive (Cmd_Buffer_Size),
              First_Byte_Timeout_MS => First_Byte_Timeout_MS);
      begin
         Spawn.Protocol.Decode_Result
           (Data         => Response,
            Active_Bound => Positive (Cmd_Buffer_Size),
            Result       => Result);
      end;
      return Result;

   exception
      when others =>
         if Lease.Active then
            begin
               Log_A_File
                 (Filename => To_String
                    (Lease.Container.Socket_Address & ".log"));
            exception
               when others => null;
            end;
            begin
               Pool_Log
                 (Msg => "Socket "
                    & To_String (Lease.Container.Socket_Address)
                  & " abandoned");
            exception
               when others => null;
            end;
            Lease_Guards.Abandon (Lease);
         else
            Log_A_File
              (Filename => To_String
                 (Lease.Container.Socket_Address & ".log"));
         end if;
         raise;
   end Send_Receive;

   -------------------------------------------------------------------------

   protected body Sockets
   is
      -------------------------------------------------------------------------

      procedure Abandon_Socket (Lease : in out Lease_Guard)
      is
         Position : constant Socket_Maps.Cursor
           := Data.Find (Key => Lease.Container.Socket_Address);
      begin
         if not Lease.Active then
            return;
         end if;
         if not Socket_Maps.Has_Element (Position => Position)
           or else Active_Count = 0
         then
            raise Program_Error with "invalid abandoned manager lease";
         end if;
         Active_Count := Active_Count - 1;
         Failed := True;
         Lease.Active := False;
      end Abandon_Socket;

      ----------------------------------------------------------------------

      procedure Begin_Cleanup
        (Snapshot       : out Socket_Maps.Map;
         Pool_Directory : out Unbounded_String)
      is
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager cleanup already in progress";
         end if;
         Shutting_Down := True;
         Snapshot := Data;
         Pool_Directory := Directory;
      end Begin_Cleanup;

      ----------------------------------------------------------------------

      procedure Cancel_Initialization
      is
      begin
         if not Data.Is_Empty or else Active_Count /= 0 then
            raise Program_Error with "cannot cancel active initialization";
         end if;
         Directory := Null_Unbounded_String;
         Failed := False;
         Shutting_Down := False;
      end Cancel_Initialization;

      ----------------------------------------------------------------------

      procedure Finish_Cleanup
      is
      begin
         Data.Clear;
         Directory := Null_Unbounded_String;
         Failed := False;
         Shutting_Down := False;
      end Finish_Cleanup;

      ----------------------------------------------------------------------

      procedure Get_Socket (Lease : in out Lease_Guard)
      is
         Pos   : Socket_Maps.Cursor := Data.First;
         Found : Boolean     := False;

         procedure Set_Busy
           (Key     :        Unbounded_String;
            Element : in out Socket_Container);
         --  Set state of given socket container to busy.

         procedure Set_Busy
           (Key     :        Unbounded_String;
            Element : in out Socket_Container)
         is
            pragma Unreferenced (Key);
         begin
            Element.Available := False;
         end Set_Busy;
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager pool is shutting down";
         end if;
         if Failed then
            raise Pool_Error with "spawn manager pool has failed";
         end if;
         while Socket_Maps.Has_Element (Position => Pos) loop
            Lease.Container := Socket_Maps.Element (Position => Pos);
            if Lease.Container.Available then
               Data.Update_Element (Position => Pos,
                                    Process  => Set_Busy'Access);
               Active_Count := Active_Count + 1;
               Lease.Active := True;
               Found := True;
               exit;
            end if;
            Socket_Maps.Next (Position => Pos);
         end loop;

         if not Found then
            raise Pool_Error with
              "No free spawn manager available, increase the pool size";
         end if;
      end Get_Socket;

      -------------------------------------------------------------------------

      procedure Insert_Socket (S : Socket_Container)
      is
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager pool is shutting down";
         end if;
         Data.Insert (Key      => S.Socket_Address,
                      New_Item => S);
      end Insert_Socket;

      ----------------------------------------------------------------------

      procedure Release_Socket (Lease : in out Lease_Guard)
      is
         procedure Set_Available
           (Key     :        Unbounded_String;
            Element : in out Socket_Container);
         --  Set state of given socket container to available.

         procedure Set_Available
           (Key     :        Unbounded_String;
            Element : in out Socket_Container)
         is
            pragma Unreferenced (Key);
         begin
            Element.Available := True;
         end Set_Available;

         Pos : constant Socket_Maps.Cursor
           := Data.Find (Key => Lease.Container.Socket_Address);
      begin
         if not Lease.Active then
            return;
         end if;
         if not Socket_Maps.Has_Element (Position => Pos)
           or else Active_Count = 0
         then
            raise Program_Error with "invalid released manager lease";
         end if;
         if not Shutting_Down and then not Failed then
            Data.Update_Element (Position => Pos,
                                 Process  => Set_Available'Access);
         end if;
         Active_Count := Active_Count - 1;
         Lease.Active := False;
      end Release_Socket;

      ----------------------------------------------------------------------

      procedure Start_Initialization (Pool_Directory : String)
      is
      begin
         if Shutting_Down or else not Data.Is_Empty then
            raise Pool_Error with "spawn manager pool is already initialized";
         end if;
         Directory := To_Unbounded_String (Pool_Directory);
      end Start_Initialization;

      ----------------------------------------------------------------------

      entry Wait_For_No_Active when Active_Count = 0
      is
      begin
         null;
      end Wait_For_No_Active;
   end Sockets;

end Spawn.Pool;
