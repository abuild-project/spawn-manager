# Contributing to Spawn Manager

Thank you for contributing to Spawn Manager.

## Before starting

Use GitHub issues for ordinary bugs and feature proposals. Report potential
security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Base all new work on `master` and submit it through a pull request. The
`abuild`, `abuild-gh`, imported Codelabs and archive branches are frozen
historical references and are not development targets.

Discuss a change before implementation when it affects the public API,
protocol fields, process lifecycle, shell compatibility, privilege handling,
signal behavior, process groups or manager-pool semantics.

## Build and test environment

Use Debian Trixie or an equivalent official build environment. Normal builds
and tests must run without root privileges.

Build and test with:

```sh
make -j8
make tests
```

Run `make cov` after changing production Ada. After changing production C,
run the direct POSIX suite included by `make tests`; C coverage remains a
separate follow-up.

Run `make doc` after changing Markdown, documentation links or documentation
build rules. Run `make perf` for execution-path or performance changes.

## Compatibility and design

The separate `spawn_manager` process remains the only `fork` and `exec`
boundary. The post-fork child must not enter Ada runtime code before `execve`
or `_exit`.

The shell API retains `/bin/bash -o pipefail -c` behavior. The structured API
retains exact executable, argument, environment, directory, stream and result
semantics.

Each protocol version is fixed and fail-closed. An incompatible wire change
requires a new protocol version, updated format documentation and independent
golden-byte tests.

Lifecycle uncertainty must fail closed. A manager with uncertain setup,
transport, reset, signaling or reaping state must not return to the pool.

## Source style

Keep manually maintained Ada and C lines within 80 columns.

Ada uses three-space indentation and the surrounding GNAT style. Give every
added or materially changed subprogram declaration an adjacent semantic
contract comment. Keep packages cohesive and split procedures when control
flow or resource ownership is no longer readily visible.

C uses tabs, C11 and the existing brace style. Keep the C boundary small and
warning-free under `-W -Wall -Wextra -Werror`. Put a concise contract comment
above every C function and explain non-obvious post-fork, descriptor, signal,
process-group, reaping and kernel-fallback behavior.

Comments describe invariants and trade-offs rather than restating syntax.

## Commits and pull requests

Use Conventional Commit subjects with an optional narrow scope. Keep subjects
at 50 characters or fewer and body lines at 72 characters or fewer.

Do not add Abuild Jira identifiers, generated sign-offs or co-author trailers.
Keep commits focused, bisect-clean and accurately described.

Update `README.md`, `CHANGELOG.md`, the protocol or lifecycle documents and
`WORK_QUEUE.md` when the change affects their contracts or accepted future
work.

Before requesting review, re-read the complete diff, run the relevant tests,
verify documentation links and generated output, and leave the worktree clean.
