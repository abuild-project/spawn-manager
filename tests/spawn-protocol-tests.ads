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

with Ahven.Framework;

package Spawn.Protocol.Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Exec_Golden_Data;
   --  Pin the complete independent-stream exec frame.

   procedure Exec_Merged_Golden_Data;
   --  Pin mode 2's exact pathless encoding and reject stdout self-reference.

   procedure Exec_Rejects_Invalid_Data;
   --  Verify malformed and semantically invalid exec requests are rejected.

   procedure Exec_Roundtrip_And_Bounds;
   --  Verify lossless exec-request fields and vector limits.

   procedure Header_Bounds;
   --  Verify fixed and active complete-frame bounds.

   procedure Header_Golden_Data;
   --  Verify exact version 2 header bytes and decoding.

   procedure Header_Rejects_Invalid_Data;
   --  Verify malformed magic, version, kind and header length rejection.

   procedure Initialize (T : in out Testcase);
   --  Register protocol tests.

   procedure Result_Golden_Data;
   --  Verify exact version 2 bytes for every result alternative.

   procedure Failure_Stage_Golden_Data;
   --  Verify every unchanged spawn-failure stage number independently.

   procedure Result_Rejects_Invalid_Data;
   --  Verify malformed and semantically invalid results are rejected.

   procedure Result_Roundtrip_Alternatives;
   --  Verify every result alternative and the diagnostic boundary.

   procedure Shell_Golden_Data;
   --  Verify exact version 2 shell-request bytes and decoding.

   procedure Shell_Rejects_Invalid_Data;
   --  Verify malformed and semantically invalid shell requests are rejected.

   procedure Shell_Roundtrip_And_Bounds;
   --  Verify lossless shell-request fields and the string limits.

end Spawn.Protocol.Tests;
