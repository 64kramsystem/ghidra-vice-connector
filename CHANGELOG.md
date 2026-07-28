# Changelog

## Unreleased

- `tools/release` now accepts an exact `X.Y.Z` release version as well as `major`, `minor`, or `patch`, and no longer runs test suites before building and publishing a release.

- Added display capture: `c64_vice_v1_capture_display` returns one rendered frame as a
  base64 indexed buffer (row-major, one byte per pixel, each byte an index into the
  returned palette by array position) together with the debug geometry, the inner
  screen rectangle, the palette from `palette get`, and the VICE version and revision.
  The connector deliberately returns the raw buffer rather than an encoded image: PNG
  encoding needs no emulator and is unit-testable upstream. Capability
  `display.capture`; `surface_revision` is now `2`.

  Capture requires a **stopped** target and refuses `running` or `unknown` before
  sending anything. Reading a frame looks harmless, but sending any binary-monitor
  command traps VICE into the monitor, which emits registers and `STOPPED`; a capture
  advertised as read-only would stop the emulator and then report that nothing changed.
  For a frame mid-execution, call `interrupt`, `capture_display`, `resume`.

  `display get` is **gated on the VICE build**. Before r46020, VICE sized the response
  four bytes short of what it writes and overran its own allocation *before* replying,
  so no client-side validation can make an affected build safe — the command is simply
  never sent to one. A build reporting a revision is judged by it (`>= r46020`); a
  release build, which reports no revision at all, is judged by its release family
  (`>= 3.11`); anything unparseable, or a connection whose build is not yet known, is
  refused. A refusal is `vice_unsupported_build`, naming the detected build and the
  requirement; a malformed `VICE_INFO` stays `vice_protocol_error`.

- `ViceBmpClient.vice_info()` now returns the full `ViceInfo` record — every version
  component plus `revision`, which is `None` on a release build — instead of a
  truncated `"major.minor.build"` string that discarded the `SVN` field. The build
  guard needs both halves. `controller.vice_version` consequently reports every
  component VICE sends (`3.10.0.0`, not `3.10.0`), and `controller.vice_revision` is
  new.

- Fixed the binary-monitor bind address. The launcher passed a bare `HOST:PORT` to
  `-binarymonitoraddress`; VICE 3.10 accepts that argument, binds nothing, and logs no
  error, so the launcher's port wait spun for its full 30 seconds and the launch failed
  with a timeout that blamed the port rather than the argument. It now passes the
  documented URI form — `ip4://HOST:PORT`, or `ip6://[HOST]:PORT` for an IPv6 literal —
  and only for the bind address; client-side connects stay plain host and port. The same
  correction applies to `README.md`, the connect-only launcher's description, and the
  CI job that starts VICE for the live suite.

- Added `tools/release <major|minor|patch>`, replacing the retired CI release job.
  One command: it refuses unless the checkout is on the default branch, clean and
  exactly in sync with origin, then writes `CONNECTOR_VERSION`, regenerates the
  published contract from it, rolls the changelog, runs the local runtime tests,
  builds the extension, commits, tags, pushes, and creates the GitHub
  release marked latest — these releases being the only way to install without a
  JDK, Gradle and a Ghidra install. Everything that can fail runs before the push;
  a pushed tag cannot be retracted, so re-running the command reports that tag as
  released rather than bumping again. The changelog is rolled before the build because
  `buildExtension.gradle` copies the project root, so a stale one would ship
  inside the zip — which `prepare` now checks. The live-VICE suite needs a running
  emulator, so it remains in CI rather than the local release path.

- Versioning moves to semantic versions, starting at `0.99.0`. `CONNECTOR_VERSION`
  in `contracts.py` is the source of truth, and the packaged extension now carries
  it as `connectorVersion` so an installed copy can be identified without a
  running connection. `extension.properties`' own `version` field is still
  Ghidra's, substituted from `application.version`, because the installer gates on
  exactly that.
- Removed `connector.version` from the published API contract. It is release
  metadata rather than part of the `c64.vice/1` compatibility surface — nothing
  compares it — and keeping it there forced a coordinated commit in
  `ghidra-mcp-c64` on every release, enforced only by an opt-in test. The version
  is still returned by `status` and capabilities.

- Fixed a protocol error raised when more than one checkpoint-info event arrived
  before a stopped event. VICE reports every matching checkpoint at an address,
  so both a repeatedly-firing non-stopping checkpoint and two overlapping
  stopping checkpoints could break the connection. Stopped events now carry a
  `checkpoints` array alongside the existing singular `checkpoint`, and
  non-stopping hits are published immediately as `checkpoint_hit` events.
- Fixed `wait_for_stop` reporting `event_history_lost` after heavy
  checkpoint-hit traffic evicted history without losing any stopped event.
- Bounded unsolicited event draining so a continuously firing non-stopping
  checkpoint can no longer starve `interrupt` and other commands of the
  operation lock.
- Added a "Mute audio output" launch option, on by default, that starts VICE with
  `-soundvolume 0`. SID emulation is unaffected, so register-level audio
  debugging still works; only host output is silenced. Untick the option, or pass
  a later `-soundvolume` through "Extra VICE args", to hear the emulator.
- Added the versioned `c64.vice/1.0` TraceRMI automation API and packaged
  capability/method contract.
- Replaced fire-and-forget execution commands with correlated acknowledgements
  and ordered stopped/resumed event synchronization.
- Added bank-aware memory, dynamic registers, checkpoints, bounded event
  history, structured timeout/partial-write errors, and one shared GUI/API
  controller.
- Relicensed the maintained connector to Apache-2.0 with original-project
  attribution in `NOTICE`.
- `tools/release` now exits successfully when HEAD already carries its release
  tag, reporting that there is nothing to release rather than failing. A release
  tags its own commit, so a tagged HEAD is the record that this commit was
  released — and until now a re-run over one was an error: either
  `ensure_tag_absent` refused, or `resumable_version` fired first and
  re-attempted `gh release create` for a release that already existed, which
  fails. That is what makes `~/code/scripts/release_ghidra_tools`, running this
  script alongside GhidraMCP-next's and c64-mcp's, re-runnable after any one of
  them fails: a repository with nothing new is a no-op, not a failure that stops
  the sweep. Only `v<semver>` tags count, so the old `v12.1-<timestamp>` tag is
  not mistaken for a release of this version line. The publish-only resume path
  is removed with it: a publish that fails after the push now leaves a tagged
  HEAD that reads as released, so finish that case by hand with
  `gh release create` — no local state distinguishes it from a completed
  release, and guessing the other way would re-publish.
