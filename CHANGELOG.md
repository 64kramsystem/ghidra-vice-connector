# Changelog

## Unreleased

- Added the versioned `c64.vice/1.0` TraceRMI automation API and packaged
  capability/method contract.
- Replaced fire-and-forget execution commands with correlated acknowledgements
  and ordered stopped/resumed event synchronization.
- Added bank-aware memory, dynamic registers, checkpoints, bounded event
  history, structured timeout/partial-write errors, and one shared GUI/API
  controller.
- Relicensed the maintained connector to Apache-2.0 with original-project
  attribution in `NOTICE`.
