# Local gui-smoke reproduction environment

Local environment for this repo (dev box, captured 2026-06-02).

## Setup

- Ghidra 12.1 at `~/local/ghidra` (symlink → `ghidra_12.1_PUBLIC`); has `support/buildExtension.gradle`, `support/launch.sh`, `support/analyzeHeadless`, and the `Debugger-rmi-trace/pypkg`.
- Default `java` is JDK 21.0.11 (matches what the Gradle 9.2.1 wrapper requires).
- The build works locally and is green:
  ```
  JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 GHIDRA_INSTALL_DIR=~/local/ghidra ./gradlew --no-daemon clean buildExtension
  ```
  → produces `dist/ghidra_12.1_PUBLIC_*_ghidra-vice-connector.zip` (`dist/` is gitignored).
- `pytest`: 289 passed, 34 skipped (the skipped are the live-VICE suite that auto-skips with no emulator).
- GUI-smoke deps present: `marco` (WM), `Xvfb`, `xdotool`, imagemagick `import`, `nc`.
- `x64sc` on PATH is the user's from-source **VICE 3.10** at `~/bin/x64sc`. It is configured via `~/.config/vice/vicerc` with NON-default locations: `Directory="/usr/share/vice"` (GLSL shaders, gresource, fonts) and explicit `KernalName`/`BasicName`/`ChargenName` under `~/comp/emulation_bioses/c64/`. There is also a distro `/usr/bin/x64sc` = **VICE 3.7.1** (same version CI uses), and a complete distro data tree at `/usr/share/vice` (apt `vice` package).

## Why test/gui-smoke/run.sh fails locally

This is a LOCAL-setup mismatch, NOT the CI cause (see `gui-smoke-ci-failure.md`).

run.sh exports `HOME=$TMP_BASE/home` and `XDG_CONFIG_HOME=$HOME/.config` (run.sh:64-65) for isolation, so VICE never reads the user's `~/.config/vice/vicerc`. It falls back to the empty `/usr/local/share/vice` (the from-source binary's compiled datadir), fails to find ROMs/shaders, and machine init fails at the `start_vice` gate. CI does not hit this because the distro VICE keeps its data in a HOME-independent system datadir.

To run the smoke test locally, VICE data must be made HOME-independent (e.g. populate `/usr/local/share/vice`, symlink data into a search-path dir, or have the test inject a vicerc). The script's `VICE_C64_ROM_DIR` hook supplies ROMs via `-kernal/-basic/-chargen` but NOT the GLSL shaders, so VICE still dies on `Could not open vertex shader: viewport.vert` with ROMs alone.
