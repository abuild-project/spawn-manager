# Spawn Manager protocol version 2

This document defines the byte-level protocol shared by the Spawn Manager
library and executable. Version 2 has no handshake, capability negotiation,
request identifiers or optional flags. A library and manager from one Abuild
bundle use the same fixed version; a mismatch is rejected.

The released [version-1 format](protocol-v1.md) remains historical. Version 2
adds only explicit shared output; field order, bounds and lifecycle remain.

All offsets are zero-based byte offsets. Every integer is big-endian. Integers
are unsigned unless explicitly marked `i64`; that field is signed
two's-complement and uses the same big-endian byte order. Lengths count bytes
rather than Ada characters. Strings retain their exact non-NUL bytes; the
protocol applies no text encoding, shell quoting or normalization.

The normative constants and field order are maintained in
[`Spawn.Protocol`](../src/spawn-protocol.ads). Independent golden-byte tests
pin both request variants, all result variants and every failure-stage value.

## Common frame

Every request and response is one exact frame:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `SPWN` |
| 4 | 2 | protocol version, fixed value `2` |
| 6 | 2 | message kind: `1` shell, `2` exec, `3` result |
| 8 | 4 | payload length, excluding this 12-byte header |

The fixed maximum frame size is 128 KiB. The pool selects one active bound for
requests and responses when it starts the manager. That bound must be at least
30 bytes, the smallest legal shell-request frame, and cannot exceed the fixed
maximum. Unknown versions or message kinds, inconsistent lengths, invalid
field values and trailing bytes are rejected.

Reusable encodings are:

```text
string  := u32 byte_length, u8[byte_length]
vector  := u32 element_count, element[element_count]
timeout := i64 two's-complement milliseconds
```

`-1` is the only negative timeout and means unlimited. Strings are limited to
64 KiB, vectors to 1,024 elements and diagnostics to 4 KiB, subject also to the
active frame bound.

## Shell request

A shell request uses message kind `1` and this payload:

```text
string command
string working_directory
i64    timeout
```

The command must contain at least two bytes. It inherits the manager's complete
environment and is normalized to:

```text
/bin/bash -o pipefail -c command
```

Standard input, output and error use `/dev/null` unless the command performs
its own shell redirection. The shell request preserves the public
command-string API and its Bash syntax; it is not a structured request encoded
as a quoted command.

## Structured exec request

An exec request uses message kind `2` and this payload:

```text
string executable
u32    argument_count
string argument[argument_count]
u32    environment_count
repeat environment_count times:
    string environment_name
    string environment_value
string working_directory
stream standard_output
stream standard_error
i64    timeout
```

The executable and working directory are absolute. The executable becomes
`argv[0]`; transmitted arguments start with `argv[1]`. The environment vector
replaces the manager environment completely, and a zero element count selects
an empty environment. Version 2 always connects standard input to `/dev/null`.

Environment names must be nonempty and must not contain `=` or NUL. Duplicate
names are transmitted in their original order; callers should avoid them
because lookup behavior then belongs to the executed program and its C
runtime rather than to the protocol.

## Stream encoding

A stream starts with one mode byte:

| Mode | Following field | Meaning |
| ---: | --- | --- |
| `0` | none | connect the stream to `/dev/null` |
| `1` | absolute path string | open and truncate without following a final symlink |
| `2` | none | stderr duplicates installed stdout; illegal for stdout |

An absent output file is created from mode `0666` filtered by the manager's
`umask`, matching normal shell redirection. Truncating an existing file keeps
its mode. A caller needing owner-only output should create the file with mode
`0600` before submitting the request.

## Shared output semantics

Stdout is installed first. `Merge_Stdout` on stderr duplicates fd 1 to fd 2,
sharing the same open file description and write position. The file is opened
and truncated only once, and stdout remains open. A null stdout gives stderr
the same null sink. Mode 2 has no path field; a stdout self-reference is rejected.
Equal truncate paths never select this policy implicitly.

This matches shell `> log 2>&1` at the descriptor level. It preserves the order
of writes reaching the shared sink, not the order of application-side stdio
buffers or atomic multi-line messages from concurrent writers. Separate
capture files joined later cannot implement this contract. Append, named
stdin, privilege exceptions and individual cancellation are not added.
The [version-1 lifecycle](lifecycle-v1.md) remains unchanged; stdout-open and
stderr-duplication failures retain the existing stages and errno.

## Result

A result uses message kind `3`. Its payload begins with a one-byte result kind
followed by exactly one alternative:

| Kind | Name | Remaining payload |
| ---: | --- | --- |
| `0` | exited | `u32 exit_status` |
| `1` | signaled | `u16 signal_number` |
| `2` | timed out | no additional bytes |
| `3` | spawn failed | `u16 stage`, `u32 errno`, diagnostic string |
| `4` | request rejected | diagnostic string |
| `5` | protocol failed | diagnostic string |

Spawn-failure stage values are fixed by this order:

| Value | Stage | Value | Stage |
| ---: | --- | ---: | --- |
| 0 | `No_Failure` | 9 | `Duplicate_Stdin` |
| 1 | `Enable_Subreaper` | 10 | `Duplicate_Stdout` |
| 2 | `Create_Error_Pipe` | 11 | `Duplicate_Stderr` |
| 3 | `Fork_Child` | 12 | `Change_Directory` |
| 4 | `Process_Group` | 13 | `Reset_Signals` |
| 5 | `Parent_Death` | 14 | `Close_Descriptors` |
| 6 | `Open_Stdin` | 15 | `Exec_Target` |
| 7 | `Open_Stdout` | 16 | `Wait_Child` |
| 8 | `Open_Stderr` | 17 | `Terminate_Group` |

Diagnostic text is truncated when necessary so the complete result fits the
active frame bound. The result kind, failure stage and `errno` are never
discarded to make it fit.

## Transport timing

Frames use a nonblocking stream socket. Sending a frame and completing a frame
after its first received byte each have a fixed five-second monotonic deadline.
For a finite child timeout, the first result byte is bounded by that timeout
plus the transport allowance. An unlimited child also has an unlimited
first-result-byte wait because version 2 has no heartbeat protocol.

Anet owns creation, connection and lifetime of the Unix stream socket. Exact
frame transfer is implemented by `Spawn.Transport` on its raw descriptor,
rather than by `Anet.Streams` or the generic one-operation socket I/O calls.
This split keeps partial-I/O retries, monotonic deadlines, frame bounds and
protocol error classification in the component which defines them. The
[project overview](../README.md#anet-boundary) records the rationale and the
conditions under which a future Anet transport primitive could replace that
generic I/O machinery.
