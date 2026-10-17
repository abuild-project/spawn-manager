# Spawn Manager lifecycle version 1

This document defines lifecycle contract version 1: process ownership,
cancellation and containment. The unchanged lifecycle contract applies to wire
protocol versions 1 and 2; its version is independent of the wire version.
The public API is declared in [`Spawn.Pool`](../src/spawn-pool.ads). Current
request and result encoding is defined by [protocol version 2](protocol-v2.md);
[protocol version 1](protocol-v1.md) describes the historical 0.2.0 wire format.

## Pool and leases

`Spawn.Pool.Init` requires the absolute path of the matching `spawn_manager`
binary. The library never searches `PATH`, and it passes the active frame bound
and socket address as separate arguments rather than reparsing a command
string.

Each pool creates its endpoints below one randomized mode-`0700` directory.
Relative socket addresses remain short on the wire to preserve the Unix-socket
path budget; the pool separately stores absolute cleanup paths. Cleanup also
accepts an already absent private directory, for example when a caller removes
its temporary parent through the final manager request.

Each `Execute` call owns one exclusive manager lease. An optional `Pid_Setup`
callback runs after the lease is selected and before the request is sent. An
optional `Pid_Reset` callback runs after a valid result, while that same lease
is still exclusive and before the manager becomes reusable.

Abuild uses this pair to move a long-lived manager into one worker cgroup for a
request and return it to the Abuild process cgroup afterwards. A caller that
supplies setup without reset deliberately retains manager-wide placement.

If setup, transport, reset or caller task execution fails, the complete pool
is poisoned. No manager whose ownership is uncertain becomes available for a
later request.

## Process groups and completion

Every request owns a new process group. Timeouts terminate and reap the group.
Normal leader exit also terminates and reaps remaining group members before
the exit or signal result is returned.

The leader remains unreaped until all request-group signals have been sent, so
its numeric process-group identity cannot be recycled into an unrelated
target. The manager stops publishing that identity to its signal handler
before the final reap.

If group signaling or leader reaping fails before the identity is retired, the
manager makes one final group-kill attempt and fail-stops instead of resuming
without ownership. A descendant-reap failure after retirement also fail-stops,
but does not signal the now reusable numeric identity again. The pool observes
the lost connection as a protocol failure and poisons every manager.

Leader and descendant reaping after termination have fixed grace-period
deadlines. An uninterruptible child therefore fail-stops its manager instead
of blocking pool cancellation indefinitely.

This lifecycle contract has no independent cancellation of a single request.
`Spawn.Pool.Cleanup` stops new leases, interrupts all managers, waits for active
callers to leave and cancels the complete pool.

## Privilege and descendant containment

Every request sets Linux `no_new_privs` before arming its parent-death signal.
Set-user-ID, set-group-ID and file-capability metadata cannot grant the child
new privileges or clear that signal during `execve`. The restriction is
inherited by shell children and structured-exec descendants.

This is a deliberate lifecycle compatibility boundary with no opt-out. A
future exception requires a concrete consumer, an explicit request contract
and cgroup containment because a privileged exec can clear the direct
leader's parent-death signal.

The parent-death signal covers only the direct request leader; Linux clears
that setting in children created by the target. Normal completion and
catchable manager termination signal and reap the observed process group. A
process group cannot make target-side `fork` and group signaling atomic,
however. A target that creates a new descendant concurrently with the final
group signal requires separately selected cgroup containment.

Cgroup containment is also required for descendants left by uncatchable
manager loss such as `SIGKILL` or OOM, and for a descendant that deliberately
escapes with `setpgid()` or `setsid()`. This contract does not claim those cases
from its process-group fallback alone.

## Signal and fork boundary

GNAT implements the manager's attached `SIGINT` and `SIGTERM` handlers with
interrupt-server tasks. The manager therefore has one request executor but is
not a single-threaded process. A process-local ownership mutex synchronizes the
main task with those runtime tasks across fork publication and exact leader
reaping.

Before forking, the manager normalizes `SIGCHLD` so every request leader stays
waitable even when the manager inherited `SIG_IGN` or `SA_NOCLDWAIT`. The child
starts with termination signals blocked, restores default `SIGINT` and
`SIGTERM` dispositions, and then clears the mask.

A small C module is the only post-`fork` boundary. The child enters no Ada
runtime code before `execve` or `_exit`. It performs child-only directory and
descriptor setup, reports pre-exec `errno` through the error pipe and calls
`execve`. The parent owns exact status collection, timeout cleanup and request
group supervision.

The manager binds its descriptor ceiling to `/proc/self/fd` only after a
complete scan. An open, read or close error with a finite soft descriptor
limit selects that limit before `fork`. With `RLIM_INFINITY`, the
implementation consults `sysconf(_SC_OPEN_MAX)` instead; this contract does not
claim portable support for an effectively unbounded result. If no usable
finite ceiling exists and `close_range` is unavailable, the child reports the
pre-exec `Close_Descriptors` stage instead of proceeding to `execve`. The Work
Queue retains the missing unlimited-limit fault injection and boundedness
evidence.

The attached manager signal handler invokes the synchronized C shutdown hook,
then exits. The hook closes the fork gate and kills the still-pinned group.
It then waits for the normal executor to acknowledge complete leader and
descendant reaping; it does not introduce a competing `waitpid` owner. A
mutex-protected in-progress flag spans the interval after the numeric group
identity is retired but before descendant collection finishes.

The reap acknowledgement has a fixed one-second wait, below the pool's
three-second manager wait. If the executor cannot finish, the manager
fail-stops with status 125 instead of waiting indefinitely or reporting normal
shutdown. Executor-side containment failure does not wait for itself. A
fail-stop cannot promise that uncollectable children have been reaped; their
eventual collection belongs to the next subreaper or host init. The pool owns
socket-path cleanup after the manager has terminated.

## Failure classification

Protocols 1 and 2 use one result kind for internal and child-spawn failures.
Stages that can represent manager-side supervision poison the complete pool,
including ambiguous error-pipe and process-group failures. This also includes
manager-side signal-mask restoration failures reported as `Reset_Signals`.

Stages that can only represent child-side pre-exec failures remain reusable.
The exact stage encoding is part of the
[current protocol result format](protocol-v2.md#result).
