# Spawn Manager Agent Guidance

Keep changes focused and preserve the separation between the tasking Ada
caller and the dedicated process manager.

## Scope and decisions

- Ask before changing scope, compatibility or architecture. Record an agreed
  protocol or lifecycle decision in the corresponding durable document and
  put accepted later work in `WORK_QUEUE.md`.
- Treat historical branches, tags and documents as evidence, not authority.
  Verify claims against the containing revision and current primary sources.
- Commit a completed, tested step before starting a distinct follow-up. Do not
  hand a reviewer an uncommitted or deliberately moving implementation.

## Relevant documentation

- Use `README.md` for the component overview, supported platform and normal
  build, test and installation commands.
- Read `doc/protocol-v2.md` when changing request or result fields, validation,
  transport bounds or stream handling. It defines the current fixed version.
- Use `doc/protocol-v1.md` only for comparison with the historical 0.2.0 wire
  contract, not as a current compatibility mode.
- Read `doc/lifecycle-v1.md` when changing processes, descriptors, signals,
  timeouts, cancellation, cgroup callbacks or pool cleanup.
- Update `CHANGELOG.md` for user- or integrator-visible changes. Keep planned
  work under `Unreleased` until preparing the final release commit. Move it
  under the dated version in that commit immediately before creating the
  annotated tag; if publication is abandoned, restore `Unreleased` rather
  than leaving a release entry without its tag.

## Development

- Work in a clean, durable worktree outside temporary directories.
- Use the supported Debian Trixie environment or an equivalent official build
  environment. Report when it is unavailable instead of substituting weaker
  host-toolchain evidence. Run normal development and tests without root.
- Build with `make -j8`, then run `make tests` without Make-level parallelism.
  The tests use disposable local fixtures and have no production access.
- Run `make cov` after changing production Ada and inspect the resulting line
  and function coverage; do not accept a new untested production path merely
  because the aggregate percentage remains high. For production C, run the
  direct POSIX suite and report that the current coverage target excludes C
  until the dedicated follow-up in `WORK_QUEUE.md` is implemented.
- Run `make doc` after changing Markdown, Pages links or documentation build
  rules. Run `make perf` only for execution-path or performance work.
- Build the relevant prerequisites before running a binary. Treat every CI job
  as an independent checkout and transfer required artifacts explicitly.
- For a regression, prove that the new test fails with the defect and passes
  with the fix. Run unit tests sequentially unless the test itself exercises
  concurrency.

## Source style

- Keep manually maintained Ada and C source lines within 80 columns.
- End every source and documentation file with a newline.
- Ada uses three-space indentation and the surrounding GNAT style. Align named
  associations, retain blank lines between declaration groups and logical
  phases, and keep the build warning-free without redundant `use` clauses.
- Keep each Ada package cohesive and narrowly responsible. The specification
  is its public contract: expose only what callers need, keep representation
  and lifecycle helpers private, and split a unit when protocol, transport or
  process management concerns can no longer be understood independently.
- Keep Ada procedures and functions short enough that their purpose, main
  control flow and resource ownership remain visible without scanning through
  unrelated phases. Extract a named helper when a subprogram develops several
  independent responsibilities, deeply nested branches or a second resource
  lifecycle. Prefer semantic structure over an arbitrary line-count target.
- Open in-process Ada file streams with `Form => "shared=no"` unless a
  documented contract requires shared external modification.
- For mutable Ada state reachable by concurrent requests, state whether it is
  task-local, immutable, protected or owned by one manager. Test concurrent
  access, or document and test the lifecycle invariant which excludes it.
- Give every added or materially changed Ada subprogram declaration an
  immediately adjacent semantic contract comment, including local helpers and
  test specifications. Put a blank line after each declaration/comment pair.
- Separate consecutive package-level Ada subprogram bodies with one plain
  `-------------------------------------------------------------------------`
  line. Do not add named three-line banners.
- C uses tabs for indentation, C11 and the existing brace layout. The supported
  warning set is `-W -Wall -Wextra -Werror`; do not silence it with unused
  state or casts which hide ownership or type errors.
- Put a concise contract comment immediately above every C function, including
  static helpers. State ownership, failure behavior or the relevant POSIX
  operation instead of restating the name.
- Label the non-obvious phases of long execution paths. Comments are mandatory
  around post-`fork` safety, descriptor ownership, signal masks, process-group
  identity, reaping, kernel fallbacks and fail-stop cleanup. Ordinary syntax
  and self-evident assignments do not need narration.
- Test comments explain the regression being detected and why the fixture is
  sensitive to it. Re-read every touched comment after a refactor.
- Before adding a binary, checksum or byte-manipulation primitive, inspect the
  Ada runtime and existing helpers. Keep independent test decoders and byte
  constants separate from the production encoder.

## Commits

- Use Conventional Commit subjects such as `build`, `chore`, `ci`, `docs`,
  `feat`, `fix`, `perf`, `refactor` and `test`, with an optional narrow scope.
- Reserve `fix` for released user-visible behavior. Corrections within an
  unreleased series use the type which describes the resulting change.
- Keep subjects at 50 characters or fewer and body lines at 72 characters or
  fewer. Use the body to explain motivation, behavior and important evidence;
  keep each commit bisect-clean.
- Wrap body prose into balanced paragraphs rather than leaving dangling words.
  Re-check every message against its final diff after rebases and fixups.
- Spawn Manager is an Abuild dependency repository, so commit messages omit
  the Abuild Jira ticket. Do not add generated sign-off or co-author trailers.

## Architecture invariants

- The separate `spawn_manager` process is the only `fork`/`exec` boundary.
  Tasking callers communicate with it over Unix-domain sockets.
- The command-string API retains `/bin/bash -o pipefail -c` behavior and the
  manager environment. Structured requests retain exact executable, argument,
  replacement-environment, working-directory, stream and result semantics.
- Each protocol version is fixed and fail-closed. Wire changes require an
  explicit new version, updated format documentation and independent
  golden-byte tests.
- The post-`fork` child enters no Ada runtime code before `execve` or `_exit`.
  Keep the C boundary small, readable and limited to async-signal-safe child
  operations; explain non-obvious ownership and cleanup steps in comments.
- Lifecycle uncertainty is fail-closed. Setup, transport, reset, signal,
  process-group or reap failures must not expose an uncertain manager for
  reuse.
- Preserve short relative socket addresses on the wire and separately captured
  absolute cleanup paths. Preserve mandatory `no_new_privs` for both request
  types unless a future protocol version defines a reviewed exception.

## Branch and release policy

- `master` is the protected canonical upstream and the only branch for new
  development and releases. Change it through reviewed pull requests; never
  rebase or force-push its published history.
- `abuild` records the final separate Abuild integration line through release
  0.2.0. `abuild-gh` records the former GitHub CI overlay and its reviewed
  merge history. Both branches are frozen historical references; do not base
  new work on them or advance them.
- Preserve imported historical branches without rebasing or rewriting them.
  Their APIs are evidence, not supported alternatives to `master`.
- Component releases use annotated stable tags named `vMAJOR.MINOR.PATCH`.
  Pure test or documentation changes do not require a release tag.
- Historical 0.1.x tags follow Abuild's maintained Gitlink sequence even where
  that sequence moved between Spawn Manager branches.
- Keep accepted follow-up work in `WORK_QUEUE.md`; assign a ticket before
  implementation or delivery rather than hiding future scope in a review note.

## Code review rules

1. Reject changes that move `fork` into a tasking caller, enter Ada after
   `fork`, or introduce non-async-signal-safe child work before `execve`.
2. Reject silent shell, argv, environment, stream, error-result or wire-format
   regressions. Require the corresponding compatibility or golden-byte test.
3. Reject any lifecycle path that can reuse a manager after uncertain setup,
   containment, signaling or reaping, or that regresses socket-length and
   `no_new_privs` guarantees.
4. Re-read the complete diff after code, tests and documentation have settled.
   Verify test sensitivity, concurrency, protocol and lifecycle documentation,
   changelog and work-queue consistency, commit-message limits, whitespace and
   a clean worktree before asking for external review.
5. Keep internal product, customer and infrastructure names out of permanent
   source, fixtures, documentation and commit messages unless their spelling is
   part of a public interface under test.
