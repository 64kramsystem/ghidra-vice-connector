# Changelog

## Unreleased

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
