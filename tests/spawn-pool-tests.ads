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

with Ahven.Framework;

package Spawn.Pool.Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Initialize (T : in out Testcase);
   --  Initialize testcase.

   procedure Caller_Abort_Releases_Lease;
   --  Verify task abort cannot strand an active manager lease.

   procedure Execute_Bin_True;
   --  Execute /bin/true.

   procedure Execute_Bin_False;
   --  Execute /bin/false, should raise an exception.

   procedure Execute_Nonexistent;
   --  Execute nonexistent command, should raise an exception.

   procedure Execute_Complex_Command;
   --  Execute complex command.

   procedure Execute_Nonterminating_Command;
   --  Execute non-terminating command.

   procedure Execute_Shell_Environment;
   --  Verify that shell requests inherit the manager-start environment.

   procedure Execute_Shell_Syntax;
   --  Verify Bash evaluation, pipefail and reuse after command failure.

   procedure Execute_Signal_Mask;
   --  Verify the shell child starts without inherited blocked signals.

   procedure Execute_Structured;
   --  Verify structured results, checked execution and timeout mapping.

   procedure Execute_Merged_Streams;
   --  Pin ordered shared logs, rejection, timeout and two-manager isolation.

   procedure Execute_Structured_Environment;
   --  Verify replacement environments remain isolated after all outcomes.

   procedure Execute_Working_Directories;
   --  Verify per-request directories and reuse after a rejected directory.

   procedure Failed_Init_Cleanup;
   --  Verify an unregistered manager and its private directory are cleaned.

   procedure Parallel_Execution;
   --  Verify parallel command execution.

   procedure Pid_Reset_Precedes_Release;
   --  Verify manager reset runs while its pool lease remains exclusive.

   procedure Pid_Setup_Structured_Target;
   --  Verify structured Pid_Setup receives the long-lived manager PID.

   procedure Pid_Setup_Target;
   --  Verify Pid_Setup receives the long-lived manager PID.

   procedure Pool_Depleted;
   --  Verify exception handling if pool is depleted.

   procedure Protocol_Failure_Poisons_Pool;
   --  Verify a manager which reports protocol failure is never reused.

   procedure Supervision_Failures_Poison_Pool;
   --  Verify every supervision-capable stage fails the complete pool closed.

   procedure Relative_Socket_Transport;
   --  Verify a short relative socket survives an overlong absolute spelling.

   procedure Command_Timeout;
   --  Test command timeout feature.

   procedure Directory_Collision_Ownership;
   --  Verify a failed mkdir cannot transfer foreign-directory ownership.

   procedure Directory_Chmod_Failure_Cleanup;
   --  Verify a post-mkdir chmod failure cleans the directory now owned.

   procedure Duplicate_Init;
   --  Verify rejected reinitialization cannot mutate a live pool.

   procedure Invalid_Manager_Path;
   --  Verify the manager executable must be supplied as an absolute path.

   procedure Invalid_Manager_Path_Nul;
   --  Verify the manager executable cannot be truncated at a C boundary.

   procedure Invalid_Protocol_Buffer_Size;
   --  Verify the pool rejects a bound below the smallest shell request.

   procedure Invalid_Shell_Command;
   --  Verify short compatible commands retain the Command_Failed contract.

   procedure Invalid_Socket_Directory;
   --  Verify error behavior with invalid socket directory.

   procedure Invalid_Socket_Directory_Nul;
   --  Verify the socket root cannot be truncated at a C boundary.

   procedure Invalid_Socket_Path;
   --  Verify error behavior with invalid (UNIX) socket path.

   procedure Invalid_Socket_Path_Relative;
   --  Verify that an invalid relative path reports the selected address.

   procedure Cleanup_Relative_Socket;
   --  Verify cleanup after a manager changes its working directory.

   procedure Cleanup_Removed_Pool_Directory;
   --  Verify cleanup accepts an externally removed private socket directory.

   procedure Cleanup_Socket_After_Delete_Error;
   --  Verify cleanup continues after a manager socket cannot be deleted.

   procedure Cleanup_Survives_Log_Error;
   --  Verify a failing cleanup diagnostic cannot lock the pool lifecycle.

   procedure Registered_Manager_Log_Failure_Cleanup;
   --  Verify a ready-log failure leaves registered-manager cleanup pool-owned.

   procedure Log_A_File;
   --  Test Log_A_File procedure;

   procedure Connect_Retry_On_Refused;
   --  Verify behavior of retry logic if connection fails with connection
   --  refused error.

   procedure Timeout_Descendant_Group;
   --  Verify that timeout kills and reaps a command's in-group descendant.

end Spawn.Pool.Tests;
