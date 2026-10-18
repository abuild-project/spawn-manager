# Spawn Manager GitHub CI environment

This repository is the canonical Spawn Manager upstream. The project was
initially developed at [codelabs.ch](https://www.codelabs.ch/); its imported
branches remain available as historical evidence.

`master` is the protected development and release branch. The former `abuild`
integration line and `abuild-gh` GitHub overlay are frozen at the 0.2.0
transition. They retain earlier Gitlinks, reviews and overlay merge history,
but receive no new development or releases.

The `run` helper builds a minimal Debian Trixie image and starts it as the
invoking host user. Its root filesystem is read-only, its network is disabled
by default after the image build, and the repository is mounted read-write at
`/work`. GitHub Actions and local development use the same entry point.

Run the complete build and test sequence from the Spawn Manager repository
root:

```sh
.github/ci/run /bin/sh -c '
  set -eu
  test "$(id -u)" -ne 0
  make clean
  make -j8
  make tests
'
```

The test runner is deliberately invoked without GNU Make parallelism so its
output and failure ordering stay deterministic. With no command, `run` opens
an interactive shell in `/work`:

```sh
.github/ci/run
```

Build the documentation with the same image:

```sh
.github/ci/run /bin/sh -c '
  set -eu
  test "$(id -u)" -ne 0
  make doc
'
```

The generated HTML landing page, changelog, work queue, historical protocol 1,
current protocol 2 and unchanged lifecycle contract are written below
`doc/html/`.

Set `SPAWN_CI_IMAGE` to override the local image name,
`DOCKER_PLATFORM` to override the default `linux/amd64` platform, and
`SPAWN_CI_NETWORK` to override the default `none` network mode.

The weekly release-integrity workflow verifies every repository tag against
`.github/maintained-release-tags`. Each published row pins the stable semantic
version, peeled target commit and complete annotated tag object. A planned tag
may be absent; a published tag must remain present and byte-identical. The
workflow never creates, updates or deletes refs.

The manifest remains the release registry after the reconstructed 0.1.x
history. For each later release use this order:

1. Finalize the source release commit and changelog on `master`.
2. Add the stable tag name, that commit's full object ID, state `planned` and
   tag-object placeholder `-` to `.github/maintained-release-tags`, then review
   and merge the policy change.
3. Create and publish the annotated tag at exactly that source commit.
4. Change its manifest state to `published` and replace `-` with the annotated
   tag object's full ID in a reviewed follow-up. That state makes later
   deletion or rewriting an integrity failure.

Do not reserve a target commit before the release commit is final, and do not
guess the annotated tag object before it has been created.
