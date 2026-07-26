# Changelog

## Unreleased

- Added `tools/release`, replacing the retired CI release job. `prepare
  --major|--minor|--patch` writes `CONNECTOR_VERSION`, regenerates the published
  contract from it, rolls the changelog, runs the gates against that candidate,
  builds the extension, then commits, records a manifest and tags. `publish`
  creates the GitHub release from the pushed tag and marks it latest, since these
  releases are the only way to install without a JDK, Gradle and a Ghidra
  install. The changelog is rolled before the build because
  `buildExtension.gradle` copies the project root, so a stale one would ship
  inside the zip — which `prepare` now checks. The live-VICE suite is excluded
  from the release gates and says so: it needs a running emulator, and CI covers
  it on every push.

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
