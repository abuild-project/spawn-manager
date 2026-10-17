# Spawn Manager Work Queue

This is the maintained list of accepted follow-up work after the initial
structured-execution delivery. It records concrete consumers and known
boundaries without silently extending protocol version 1. Assign a ticket and
define acceptance evidence before starting an item.

## Post-0.2.0 validation

- Complete the remaining native performance measurements on every release
  architecture and retain paired shell, structured-manager and direct-core
  medians.
- Continue validating the released revision through Abuild's recursive
  checkout, archive, install, reference-product and user-interrupt system
  tests. Record any discovered defect for a patch release rather than moving
  the version 1 contract silently.

## Accepted follow-ups

### Neutral GitHub organization

The canonical repository initially remains under its current personal GitHub
namespace so the Codelabs redirect and upstream transition do not depend on a
new governance decision. Reconsider a transfer to a neutral project
organization after its permanent name, repository scope and at least two
trusted organization owners are confirmed.

Before a transfer, inventory repository and Pages URLs, Actions permissions,
installed review applications, Dependabot, secrets and branch and tag rules.
Afterward, republish Pages, update the Codelabs redirect and verify web, clone,
fetch, CI and release access through both the old and new repository URLs.

### Shared output sink and Abuild `make` migration

Exec V1 has independent null-or-truncate stdout and stderr streams. Pointing
both at one pathname would open and truncate it twice and would not preserve
the historical ordered combined build log, so component `make` remains an
intentional shell caller.

Define and test one shared open-file-description stream policy, either as an
explicitly compatible V1 completion before release or as protocol V2. Preserve
ordered stdout/stderr, cgroup placement, complete argv logging and Ctrl-C
cleanup, then migrate `make -s -jN -C PATH` to structured execution.

### Remaining Abuild shell callers

Eleven production shell sites remain for configured scripts, pipelines or
append/merge behavior. Raw shell values require explicit quoting. After the
shared-stream decision, re-audit the allowlist and migrate every caller which
no longer needs shell syntax. Keep configured `runcmd` source explicit rather
than pretending it is argv data.

### Explicit privilege-gaining execution

Version 1 applies `no_new_privs` to every shell and structured request and has
no exception. Add an opt-in only for a concrete transformation which requires
privilege metadata during `execve`. Specify it in a new protocol contract and
require cgroup containment because privileged exec may clear the direct
leader's parent-death signal.

### Individual request cancellation

Version 1 cancels the complete pool through `Cleanup`; it has no request
identifier or single-request cancel operation. Add this only for a concrete
concurrent consumer. Define identity, races, result classification and manager
reuse before choosing a wire format.

### Descriptor-ceiling fallbacks

A failed `/proc/self/fd` scan with a finite soft descriptor limit selects and
caches that limit. If the limit is `RLIM_INFINITY`, the current implementation
consults `sysconf(_SC_OPEN_MAX)`; its result is not yet an accepted portable
version-1 contract. Add fault injection for an unlimited limit with both
procfs and `close_range` unavailable. The request must fail at descriptor
closure instead of attempting an effectively unbounded sweep.

Separately measure whether caching a finite fallback after a transient procfs
failure has a material cost. If so, define a bounded retry or refresh rule
without allowing a partial procfs scan to lower the ceiling.

### Invalid-descriptor diagnostics

Transport deadline checks may win over `POLLNVAL`, changing diagnostic
specificity but not safety. Add a focused fault injection and reorder only if
the more precise diagnosis is stable across supported kernels.

### Direct C coverage

The current `make cov` target reports Ada coverage only; the direct POSIX suite
tests `spawn-posix.c` without coverage instrumentation. Add a dedicated C
coverage path which retains the wrapped-syscall fault fixtures and disposable
subprocess isolation, then publish its line and function result separately from
the Ada report. Do not treat the Ada percentage as evidence for the C core.

Abuild-specific scheduling, real cgroup-provider validation and source
acquisition remain in Abuild's own plans and work queue. This component queue
records only the Spawn Manager contract needed by those consumers.
