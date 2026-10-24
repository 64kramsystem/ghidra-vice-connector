# Agent instructions

- `$GHIDRA_INSTALL_DIR` identifies the installation
- Use `$GHIDRA_SOURCE_DIR` and/or `$VICE_SOURCE_DIR` when source can replace guesswork
- Record public-contract changes in `CHANGELOG.md`; release via `tools/release <major|minor|patch>`, following semver

- Target Ghidra 12.2 and JDK 25 only; do not retain support for older Ghidra or Java releases.
