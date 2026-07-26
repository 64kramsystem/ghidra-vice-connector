# Changelog

## Unreleased

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
