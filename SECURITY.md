# Security Policy

## Supported versions

| Version or branch | Supported |
| --- | --- |
| Latest `0.2.x` release | Yes |
| `master` before the next release | Best effort |
| `0.1.x` releases | No |
| Historical and archive branches | No |

Security fixes are released from the protected `master` branch. Historical
tags and frozen branches remain available for provenance but do not receive
security updates.

## Reporting a vulnerability

Do not report a potential vulnerability through a public issue, pull request
or discussion.

Use GitHub's private vulnerability reporting for this repository:

https://github.com/abuild-project/spawn-manager/security/advisories/new

Include the affected version, platform, realistic impact, relevant
configuration and the smallest useful reproduction. Remove credentials,
private keys, customer data and unrelated logs.

We will use the private advisory to validate the report and coordinate a fix,
release and disclosure. This project does not promise a fixed response or
remediation deadline.

## System and scope

Spawn Manager lets a multitasking Ada application execute child processes
without calling `fork` from the application's tasking runtime. A pool of
long-lived manager processes receives bounded requests over private local
Unix-domain sockets and owns `fork`, `execve`, supervision and reaping.

The supported execution core is Linux-specific. The security boundary covers
the Ada pool, protocol and transport, the C execution core, manager
executable, Unix sockets and their integration contracts.

The embedding application is trusted to request process execution. Executable
paths, arguments, environment entries, working directories and output paths
may still contain attacker-controlled data when a consumer passes such data
through, so Spawn Manager must preserve their documented boundaries exactly.

## Security invariants

- Only the dedicated manager process performs `fork` and `execve`.
- No post-fork child enters Ada runtime code before `execve` or `_exit`.
- Protocol frames are versioned, length-bounded, validated and fail closed.
- Pool sockets remain private, correctly owned and safely cleaned up.
- Structured requests preserve exact arguments and replacement environments
  without shell parsing.
- Version 1 applies `no_new_privs` to every request child.
- Unexpected descriptors are not inherited by request children.
- Signal state is normalized without losing manager or child observability.
- Each request has a supervised process group with bounded termination and
  reaping. Cleanup covers descendants which remain in that group; callers
  need cgroup containment for descendants which escape through `setpgid` or
  `setsid`, or arise during the final-signal race.
- Setup, transport, reset, containment or reaping uncertainty prevents manager
  reuse and poisons the pool where required.
- Setup and reset callbacks run while the selected manager lease is exclusive.

## Reportable findings

Examples include:

- bypassing frame validation, size limits or protocol-version checks;
- cross-user request injection through socket permissions or path handling;
- unintended descriptor or sensitive environment inheritance;
- failure to terminate or reap processes which remain within the documented
  process-group or caller-supplied cgroup containment boundary;
- privilege gain despite the version 1 `no_new_privs` contract;
- unsafe post-fork behavior in the multithreaded caller boundary;
- reuse of a manager whose supervision or lifecycle state is uncertain;
- argument, environment, stream or working-directory confusion that crosses a
  documented trust boundary;
- memory corruption or reliably exploitable resource exhaustion in supported
  configurations.

## Out of scope

The following are not security vulnerabilities by themselves:

- behavior confined to unsupported `0.1.x`, historical or archive branches;
- lack of support for non-Linux operating systems;
- shell interpretation requested through the command-string API;
- shell injection caused solely by a caller embedding unquoted untrusted data
  in a shell command string;
- intentional execution of an arbitrary command requested by the trusted
  embedding application;
- resource consumption caused solely by a trusted caller intentionally
  requesting an unlimited or expensive process;
- a dependency vulnerability that does not cross a Spawn Manager integration
  boundary.

Ordinary correctness, documentation and performance problems without a
realistic security impact should be reported through a public issue.

## Known limitations

The local Unix socket is not an authorization boundary against other code
already running with the same operating-system identity.

Version 1 has no privilege-gaining execution mode and no individual-request
cancellation operation. Cgroup placement is supplied by trusted caller
callbacks and is not part of the wire protocol.

Anet owns socket lifecycle and addressing. Spawn Manager owns frame encoding,
exact transfer, validation, deadlines and protocol-failure classification.
