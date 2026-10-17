# Ada Spawn Manager

Spawn Manager lets a multitasking Ada program execute child processes without
calling `fork(2)` from the application's tasking runtime. The application
starts a pool of dedicated manager processes early; later requests cross a
Unix-domain socket, and only a selected manager performs `fork` and `execve`.

## Motivation

> If the parent is using tasking, and needs to spawn subprocesses at arbitrary
> times, one technique is for the parent to spawn (very early) a particular
> spawn-manager subprocess whose job is to spawn other processes. The
> spawn-manager avoids tasking. The parent sends messages to the spawn-manager
> requesting it to spawn processes, using whatever inter-process communication
> mechanism you like, such as sockets.
>
> — *GNAT Compiler Components, `System.OS_Lib` specification*

The project provides two request styles:

- a compatible command-string API that executes
  `/bin/bash -o pipefail -c COMMAND`; and
- a structured API with an explicit executable, ordered argument vector,
  complete replacement environment, working directory, independent or
  explicitly shared output destinations, and timeout.

Both styles use the same bounded, versioned protocol and the same supervised
execution core. There is no intermediate `spawn_wrapper` process.

## Status and platform

The latest stable release is **0.2.0**. This development revision adds protocol
2 with shared output and requires its matching library and manager. It retains
the existing shell API. Changes are collected in the
[changelog](CHANGELOG.md); accepted later work is tracked in the
[work queue](WORK_QUEUE.md).

The current execution core is Linux-specific. It relies on Unix-domain
sockets, process groups, `prctl(2)`, `/proc` and POSIX process and signal
operations. Both versions set `no_new_privs` for every child, so shell and
structured requests cannot gain privileges through set-user-ID,
set-group-ID or file-capability metadata during `execve`.

## Execution model

`Spawn.Pool.Init` starts one or more long-lived managers from an explicit
absolute path. Concurrent callers lease different managers; one manager
handles one request at a time. Each request receives its own process group,
and the manager owns timeout handling, termination and reaping.

The shell API inherits the manager environment and preserves Bash syntax. The
structured API performs no shell parsing or quoting: arguments and environment
entries arrive as exact protocol fields. It returns distinct results for a
normal exit, signal termination, timeout, spawn failure, rejected request and
protocol failure.

Pool lifecycle failures are fail-closed. If setup, transport, reset or process
supervision leaves a manager's state uncertain, the complete pool is poisoned
instead of making that manager available to another caller.

For the exact contracts, see:

- [Protocol version 2](doc/protocol-v2.md) for the shell and structured wire
  formats, bounds and result encoding.
- [Lifecycle version 1](doc/lifecycle-v1.md) for process groups, signals,
  timeouts, reaping, `no_new_privs`, cgroup callbacks and failure handling.
- [`Spawn.Pool`](src/spawn-pool.ads) for the public Ada API.

### Anet boundary

Anet remains the socket-lifecycle abstraction. It creates and owns the Unix
stream sockets, validates addresses, connects clients, accepts manager
connections, switches descriptors to nonblocking mode and closes them. Spawn
Manager also uses Anet's operating-system constants and filesystem utilities.

Frame serialization and exact frame transfer deliberately belong to Spawn
Manager. Neither version uses `Anet.Streams`, Ada record streaming or the
generic `Anet.Sockets.Send` and `Receive` operations for protocol data. Those
socket operations each represent one system call, whereas this protocol must
resume partial reads and writes, distinguish first-byte and completion
deadlines, handle interruption and backpressure, reject trailing bytes and
classify peer closure precisely. `Spawn.Transport` therefore operates on the
descriptor owned by the Anet socket and implements those protocol-specific
rules with `poll(2)`, `recv(2)` and `send(2)`.

This boundary is intentional rather than a replacement for Anet. A future
Anet primitive offering the same exact, deadline-bounded nonblocking transfer
semantics could replace the generic I/O part without changing the current
wire format. Frame layout, validation and protocol failure classification
would remain Spawn Manager responsibilities.

## Requirements

Building Spawn Manager requires:

- a GNAT Ada compiler and `gnatmake`;
- a C11 compiler and POSIX threads;
- [Anet](https://git.codelabs.ch/?p=anet.git); and
- GNU Make.

The tests additionally require
[Ahven](https://www.stronglytyped.org/ahven/), Bash, Python 3
and standard Linux process utilities. Coverage needs `lcov` and `genhtml`.
Building the optional HTML documentation requires
[Pandoc](https://pandoc.org/).

## Build and test

Build the static Ada library and the manager executable:

```sh
make -j8
```

Run the complete Ada, protocol, transport, direct C and integration test
suite. The test runner intentionally runs without Make-level parallelism so
its process and log ordering remains deterministic:

```sh
make tests
```

The signal integration check uses its own fallback subreaper. It detects
children abandoned by a terminated manager even when a container init would
otherwise collect them. Shell and structured requests exercise both SIGINT
and SIGTERM; direct C fault tests also cover delayed and stalled reaping.
A fixture self-test checks recovery across newly adopted generations.

Run the comparative execution benchmarks:

```sh
make perf
```

The performance target covers the legacy shell path, structured requests,
small and larger output streams, manager startup and cleanup, and parallel
throughput. Its wall-clock results are meaningful as paired measurements on
the same host, not as portable absolute limits.

Useful build controls are:

- `BUILD_TYPE=debug` to enable assertions and additional warnings in the
  manager;
- `ADAFLAGS="..."` to append Ada compiler switches; and
- `CC=...` to select the compiler used by the direct C test fixtures.

Generate the HTML documentation under `doc/html/` with:

```sh
make doc
```

## Installation

Install the library, GNAT project file and manager executable with:

```sh
make PREFIX=/usr/local install
```

The default prefix is `$HOME/ada`. The manager is installed as
`$PREFIX/spawn_manager`; the static library, Ada sources and project file are
installed below the prefix's `lib`, `include` and `lib/gnat` directories.
Installation removes a stale `$PREFIX/spawn_wrapper` from earlier versions.

## Versioning

Release versions use annotated `vMAJOR.MINOR.PATCH` Git tags. The generated
`Spawn.Version` value comes from `git describe`, with the leading `v` removed.

The historical 0.1.x tags reconstruct the distinct Spawn Manager states
selected by Abuild's maintained Gitlink history. A Gitlink update that changed
only tests or documentation does not create a component version. Beginning
with 0.2.0, releases follow normal semantic versioning: compatible fixes
increment the patch version, new capabilities increment the minor version,
and an incompatible stable public contract requires a major version change.

## Source repository and history

The canonical upstream is
[github.com/abuild-project/spawn-manager][canonical-repository].
The project was initially developed at
[Codelabs](https://git.codelabs.ch/?p=spawn-manager.git); that former repository
location is retained as a redirect and historical point of reference.

[canonical-repository]: https://github.com/abuild-project/spawn-manager

The previous `mweidle73/spawn-manager` GitHub address redirects to this
repository, including Git clone, fetch and push operations. Keep that old
repository path unoccupied so existing checkouts and historical Abuild
submodule URLs retain the redirect.

The rendered documentation is available at
[abuild-project.github.io/spawn-manager/][documentation-site]. GitHub Pages
does not provide the repository transfer's automatic redirect.

[documentation-site]: https://abuild-project.github.io/spawn-manager/

`master` is the protected development and release branch. The former `abuild`
integration branch and its `abuild-gh` GitHub CI overlay are frozen at the
0.2.0 transition and retained so their Gitlinks, reviews and merge history
remain inspectable.

The imported `add_remove_managers` and `cgroups` branches preserve unmerged
Codelabs development. `archive/cgroups-caller-placement-wip` preserves the
later caller-side cgroup-placement prototype which led to the supported
`Pid_Setup` and `Pid_Reset` callbacks. These branches are historical evidence,
not maintained APIs or alternatives to `master`.

## Authors and licence

Copyright (C) 2011-2026 secunet Security Networks AG<br>
Copyright (C) 2012-2016 Reto Buerki <reet@codelabs.ch>

Authors and contributors include Reto Buerki, Adrian-Ken Rueegsegger, Matthias
Weidle and Markus Vogt. See [AUTHORS](AUTHORS).

Spawn Manager is distributed under the GNU General Public License, version 2
or later, with the GNAT Modified GPL linking exception stated in the source
headers. See [COPYING](COPYING) for the GPL text.
