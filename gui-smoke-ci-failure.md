# CI gui-smoke failure — root cause

As of 2026-06-02, on branch `ghidra-12.1-support` (PR #34), the CI `gui-smoke` job fails (red X) while `build` and `python-tests` pass. `gui-smoke` is `continue-on-error: true` and is NOT a dependency of the `release` job, so this failure does NOT block release.

## Root cause

From the run's `gui-smoke-diagnostics` artifact `vice.log` (run id 26847674654):

- CI runs **VICE 3.7.1** (Ubuntu's `vice` package; the apt package ships the emulator but not the copyrighted C64 ROMs, so the workflow downloads them from VICE-Team's `svn-mirror` at runtime).
- VICE logs `C64MEM: Error - Couldn't load kernal ROM 'kernal-901227-03.bin'` while `basic`/`chargen` (same dir, same download) load fine.
- Because the kernal load fails, VICE never prints the `C64MEM: Kernal rev #3 ($03)...` line.
- `test/gui-smoke/run.sh` `vice_boot_ready()` (run.sh:322, `VICE_KERNAL_MARKER='Kernal rev #3'`) polls for that exact string for 60s; it never appears → `die "VICE boot check timed out..."` → exit 1, all inside the `start_vice` phase (no `ghidra.log`/screenshots in the artifact confirm it died before phase 8). The monitor port DID open and the PRG DID autostart (`AUTOSTART: Done.`).

## Verified NOT a corrupt download

The kernal CI downloads is byte-identical to the known-good ROM — both SHA1 `1d503e56df85a62fee696e7618dc5b4e781df1bb`, 8192 bytes. So a *valid* kernal is being rejected by VICE 3.7.1 in CI.

## Open question

Why 3.7.1 refuses a valid kernal, and/or whether 3.7.1 even emits the `Kernal rev #3` marker at all (it may be a newer-VICE log string). Testable locally: the distro `/usr/bin/x64sc` is 3.7.1. See `local-gui-smoke-repro-env.md`.

## Fix (implemented and CI-verified)

Commit `ec4c2f9` relaxed `vice_boot_ready()` to gate on the real contract — monitor port open (already checked) plus fixture autostart success (`AUTOSTART: Done.`) — instead of the `Kernal rev #3` log string, and pinned the CI-provisioned ROMs by sha256 (subsumes the old size check).

Verified: CI run 26854133172 is the first green `gui-smoke` job (`build`/`python-tests` green as before). The later deterministic gates (`launch_ghidra`, `assert_extension_loaded`) were exercised in CI for the first time and passed.

Still open (best-effort, non-gating, by design): the end-to-end probe does not reach "Agent ready" — the xdotool "Open With → Debugger" navigation opens the context menu but the submenu click never lands, so the Debugger tool and launcher are never triggered (`vice-agent.log` absent; step screenshots 02–04 are byte-identical, 05–07 match the pre-menu frame). The `gui-smoke-diagnostics` artifact of that run has the screenshots for tuning.

Note: a self-contained bundled VICE 3.10 (binary + data) was prototyped as an alternative fix and dropped — the gate relaxation made it unnecessary. The C64 ROMs themselves are redistributable (they ship in Debian packages), so bundling remains a viable option if a version-pinned emulator is ever wanted.
