#!/usr/bin/env python3
#
# Copyright (C) 2026 secunet Security Networks AG
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

"""Require the actual manager to reap its group before catchable shutdown."""

import ctypes
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


PR_SET_CHILD_SUBREAPER = 36
WORKER = """import json, os, signal
from pathlib import Path
child = os.fork()
if child == 0:
    while True:
        signal.pause()
ready = Path('ready.json.new')
ready.write_text(json.dumps([os.getpid(), child]))
ready.replace('ready.json')
while True:
    signal.pause()
"""


def require(condition, message):
    """Make failed containment observable rather than relying on an init."""
    if not condition:
        raise AssertionError(message)


def string(value):
    """Encode one documented protocol string, not shell source."""
    data = os.fsencode(value)
    return struct.pack(">I", len(data)) + data


def request(kind, version, worker, directory):
    """Exercise both public request styles with the same descendant fixture."""
    if kind == "shell":
        # The trailing command keeps Bash as leader, with Python beneath it.
        payload = string(shlex.join([sys.executable, str(worker)]) + "; :")
        payload += string(directory) + struct.pack(">q", -1)
        message = 1
    else:
        payload = string(sys.executable) + struct.pack(">I", 1)
        payload += string(worker)
        payload += struct.pack(">I", 0) + string(directory)
        payload += b"\x00\x00" + struct.pack(">q", -1)
        message = 2
    header = struct.pack(">4sHHI", b"SPWN", version, message, len(payload))
    return header + payload


def wait_until(predicate, manager, message):
    """Bound fixture startup and fail if the manager dies before readiness."""
    deadline = time.monotonic() + 5
    while not predicate():
        require(manager.poll() is None, message + ": manager exited")
        require(time.monotonic() < deadline, message + ": timed out")
        time.sleep(0.01)


def collect_children():
    """Collect every adopted descendant, never the already waited manager."""
    adopted = []
    deadline = time.monotonic() + 5
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return adopted
        if pid:
            adopted.append(pid)
        else:
            require(time.monotonic() < deadline, "live adopted descendant")
            time.sleep(0.01)


def connect_when_ready(connection, address):
    """A bound socket can exist before the manager has started listening."""
    try:
        connection.connect(str(address))
        return True
    except (FileNotFoundError, ConnectionRefusedError):
        return False


def recover(manager):
    """Kill and reap private test subjects even when the assertion fails."""
    if manager.poll() is None:
        manager.kill()
        manager.wait(timeout=5)
    children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
    # No other subprocess is active. Unreaped children cannot reuse a PID.
    # Repeat: killing an adopted parent can expose another live generation.
    deadline = time.monotonic() + 5
    while True:
        for value in children.read_text().split():
            try:
                os.kill(int(value), signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        require(time.monotonic() < deadline, "private recovery timed out")
        time.sleep(0.01)


def check_recovery():
    """Reap three generations, including children adopted during cleanup."""
    with tempfile.TemporaryDirectory(prefix="spawn-recovery-") as temporary:
        directory = Path(temporary)
        worker = directory / "worker.py"
        worker.write_text(WORKER)
        manager = subprocess.Popen(
            ["/bin/bash", "-c",
             shlex.join([sys.executable, str(worker)]) + "; :"],
            cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
        try:
            ready = directory / "ready.json"
            wait_until(ready.is_file, manager, "recovery fixture not ready")
            members = json.loads(ready.read_text())
            require(len(members) == 2, "recovery fixture lacks generations")
            for pid in members:
                os.kill(pid, 0)
            recover(manager)
            require(not children.read_text().strip(),
                    "recovery returned with unreaped private children")
        finally:
            # Independent rescue must not depend on the helper under test.
            if manager.poll() is None:
                manager.kill()
                manager.wait(timeout=5)
            deadline = time.monotonic() + 5
            while True:
                for value in children.read_text().split():
                    try:
                        os.kill(int(value), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                require(time.monotonic() < deadline, "recovery rescue timed out")
                time.sleep(0.01)
    print("PASS signal fixture: newly adopted recovery children", flush=True)


def exercise(executable, version, kind, termination):
    """Detect orphan zombies independently of the surrounding PID 1 behavior."""
    with tempfile.TemporaryDirectory(prefix="spawn-reaping-") as temporary:
        directory = Path(temporary)
        worker = directory / "worker.py"
        worker.write_text(WORKER)
        with (directory / "manager.log").open("wb") as output:
            manager = subprocess.Popen(
                [str(executable), "8192", "manager.sock"], cwd=directory,
                stdout=output, stderr=subprocess.STDOUT)
            try:
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(5)
                    wait_until(lambda: connect_when_ready(
                        connection, directory / "manager.sock"),
                        manager, "manager socket not ready")
                    connection.sendall(
                        request(kind, version, worker, directory))
                    ready = directory / "ready.json"
                    wait_until(ready.is_file, manager, "request not ready")
                    members = json.loads(ready.read_text())
                    require(len(members) == 2, "missing descendant fixture")
                    for pid in members:
                        os.kill(pid, 0)
                    os.kill(manager.pid, termination)
                    require(manager.wait(timeout=3) == 0,
                            "catchable shutdown did not complete normally")
                adopted = collect_children()
                require(not adopted,
                        f"{kind}/{termination.name} left adopted children: "
                        f"{adopted}")
            finally:
                recover(manager)
    print(f"PASS signal reaping: {kind}/{termination.name}", flush=True)


def main():
    """Become the nearest fallback reaper and assert it is never needed."""
    executable = Path(sys.argv[1]).resolve(strict=True)
    version = int(sys.argv[2])
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0,
            "cannot enable test subreaper")
    check_recovery()
    for kind in ("shell", "exec"):
        for termination in (signal.SIGINT, signal.SIGTERM):
            exercise(executable, version, kind, termination)


if __name__ == "__main__":
    main()
