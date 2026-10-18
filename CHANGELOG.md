# Changelog

This document records user- and integrator-relevant Spawn Manager changes.
Low-level implementation details and test-only changes are omitted unless they
define a compatibility or security boundary.

Changes intended for the next release are collected under `Unreleased`. When
a release is made, that section is renamed to the released version and tag
date, and a new empty `Unreleased` section is added above it.

The 0.1.x history is reconstructed from the Spawn Manager Git history and the
successive Gitlinks on Abuild's maintained main line. Its dates record when
Abuild adopted each state, not when the retrospective annotated tag was
created. Historical branch switches are compared with the previously used
Gitlink even when the two Spawn Manager commits are not direct ancestors.

## [Unreleased]

### Added

- Added public contribution guidance and a private vulnerability-reporting
  security policy for the canonical upstream.
- Added lightweight issue and pull-request templates for public contributions.

### Changed

- Moved the canonical repository and documentation to the `abuild-project`
  GitHub organization. Updated source and private security-reporting links;
  the former repository address remains available through GitHub's redirect.
- Established the maintained GitHub repository and its protected `master`
  branch as the canonical upstream. Retained the former Codelabs development,
  Abuild integration and GitHub overlay branches as frozen history.
- Replaced Codelabs synchronization with local release-tag integrity checks.

### Fixed

- Catchable manager shutdown now waits for its executor to reap request
  descendants before exiting, including after the leader identity has been
  retired. A stalled reap acknowledgement fail-stops within a fixed bound.
  Shell and structured requests retain the existing wire format and results.

## [0.2.0] - 2026-09-27

### Added

- Added structured execution with an explicit executable, ordered argument
  vector, complete replacement environment, absolute working directory,
  independent standard-output and standard-error destinations, and timeout.
- Added a fixed, versioned and length-bounded binary protocol for shell
  requests, structured requests and execution results. Invalid versions,
  message kinds, lengths, values and trailing bytes fail closed.
- Added distinct results for normal exit, signal termination, timeout,
  child-spawn failure, rejected requests and protocol failures. Spawn failures
  retain their setup stage, `errno` and a bounded diagnostic.
- Added process-group supervision with bounded termination and reaping,
  Linux parent-death signaling, normalized `SIGCHLD` handling and
  `no_new_privs` for every request child.
- Added an optional `Pid_Reset` callback which runs while a manager lease is
  still exclusive. Together with `Pid_Setup`, it supports moving a manager
  into a worker cgroup for one request and returning it afterwards.
- Added protocol, transport and direct POSIX-core test suites, golden-byte
  format oracles, lifecycle fault injection and comparative execution
  benchmarks.

### Changed

- Routed the compatible shell API through the same supervised execution core
  as structured requests. Shell commands continue to run as
  `/bin/bash -o pipefail -c` and inherit the manager environment.
- Made the manager executable path explicit and absolute instead of searching
  `PATH` or reparsing a command string.
- Isolated each pool's sockets below a private mode-`0700` directory while
  retaining short relative socket addresses for the Unix-socket length limit.
- Made manager leasing, reset and cleanup abort-safe. Setup, transport, reset
  and ambiguous supervision failures poison the complete pool rather than
  returning uncertain manager state to another caller.
- Bounded frame completion, manager startup, timeout cleanup and descendant
  reaping with monotonic deadlines.
- Documented the protocol and lifecycle contracts separately from the project
  overview.
- Documented the intentional Anet boundary: Anet owns Unix socket lifecycle,
  while Spawn Manager owns versioned wire encoding and exact frame transfer.

### Fixed

- Preserved the shell API's historical failure mapping while retaining exact
  result details for structured callers.
- Prevented inherited ignored `SIGCHLD`, signal masks and signal dispositions
  from making request leaders unobservable or changing child behavior.
- Closed descriptor, socket, process-group identity and child-reaping gaps
  found by lifecycle and containment review.
- Kept socket cleanup correct when callers change directory or remove a
  temporary socket parent before final cleanup.
- Preserved manager ownership when logging, setup, reset or task aborts fail.

### Removed

- Removed the intermediate `spawn_wrapper` executable. The manager now owns
  both compatible shell execution and structured `execve` directly.

## [0.1.18] - 2026-08-24

### Changed

- Accepted caller-provided Ada compiler flags and pinned their propagation
  through the build.

## [0.1.17] - 2026-08-11

### Fixed

- Captured absolute cleanup paths during initialization so relative manager
  sockets remain removable after caller and manager directory changes.

## [0.1.16] - 2026-08-11

### Changed

- Bounded path diagnostics instead of constructing unbounded error text.

## [0.1.15] - 2026-08-11

### Fixed

- Hardened socket cleanup so one removal failure does not abandon the
  remaining manager state.

## [0.1.14] - 2026-08-11

### Fixed

- Removed Unix socket files correctly when the pool used a relative socket
  directory.

## [0.1.13] - 2026-06-22

### Changed

- Updated to Anet 0.4.1 and current GNAT project settings.
- Restored builds and tests on current Debian shells and compilers.

## [0.1.12] - 2026-06-19

### Fixed

- Removed obsolete Ada clauses and made executable-location tests independent
  of `/bin/bash` being the only valid Bash path.

## [0.1.11] - 2026-04-14

### Added

- Added the manager process-setup callback used by Abuild's cgroup worker
  placement.

## [0.1.10] - 2018-04-19

### Added

- Made the command receive buffer configurable and used the selected size for
  in-memory serialization streams.

## [0.1.9] - 2016-05-02

### Fixed

- Reset connection-refusal state for each retry so a later successful
  connection is not reported as failed.

## [0.1.8] - 2016-03-01

### Fixed

- Retried manager connections that encounter `Connection refused` during
  pool initialization.

## [0.1.7] - 2015-12-07

### Added

- Added a caller-provided pool logging callback and configurable manager
  socket timeout.
- Added generated version reporting and startup diagnostics.

### Changed

- Included manager log contents in initialization and transport-failure
  diagnostics when debug logging is enabled.

## [0.1.6] - 2015-11-27

### Changed

- Made the manager's production or debug build type selectable through Make.

## [0.1.5] - 2015-10-09

### Changed

- Migrated Unix socket handling to the Anet 0.2 API.

## [0.1.4] - 2012-08-30

### Changed

- Moved the manager and wrapper programs into the tools directory.

### Fixed

- Interrupted running managers during pool cleanup and terminated an active
  child when its manager exits.

## [0.1.3] - 2012-04-23

### Added

- Added a configurable socket directory to pool initialization.

### Fixed

- Rejected empty manager pools, validated socket directories and seeded
  randomized socket names with the process ID.

## [0.1.2] - 2012-03-23

### Fixed

- Added the GNAT.Expect input-descriptor workaround required by the Abuild
  integration at the time.

## [0.1.1] - 2012-03-23

### Added

- Added command timeouts.

### Changed

- Switched request serialization to Anet in-memory streams and child creation
  to nonblocking spawning.

## [0.1.0] - 2012-03-02

### Added

- Added the first Spawn Manager state consumed by Abuild: a pool of dedicated
  managers, Unix-domain-socket request transport and compatible shell command
  execution outside the caller's multitasking Ada runtime.
